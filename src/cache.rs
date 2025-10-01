use crate::config::CacheConfig;
use crate::error::{HttpCliError, Result};
use crate::request::Request;
use crate::response::Response;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tokio::fs;

#[derive(Debug)]
pub struct Cache {
    config: CacheConfig,
    dns_cache: HashMap<String, DnsCacheEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    request_key: String,
    response: CachedResponse,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    duration_ms: u64,
    version: String,
}

#[derive(Debug, Clone)]
struct DnsCacheEntry {
    addresses: Vec<std::net::IpAddr>,
    expires_at: SystemTime,
}

impl Cache {
    pub async fn new(config: &CacheConfig) -> Result<Self> {
        // Create cache directory if it doesn't exist
        if config.enabled {
            fs::create_dir_all(&config.directory).await?;

            // Clean up expired entries on startup
            let cache = Self {
                config: config.clone(),
                dns_cache: HashMap::new(),
            };

            cache.cleanup_expired().await?;

            Ok(cache)
        } else {
            Ok(Self {
                config: config.clone(),
                dns_cache: HashMap::new(),
            })
        }
    }

    /// Get cached response if available and not expired
    pub async fn get_response(&self, request: &Request) -> Result<Option<Response>> {
        if !self.config.enabled {
            return Ok(None);
        }

        let cache_key = request.cache_key();
        let cache_path = self.get_cache_path(&cache_key);

        if !cache_path.exists() {
            return Ok(None);
        }

        // Read and deserialize cache entry
        match self.load_cache_entry(&cache_path).await {
            Ok(entry) => {
                // Check if entry is expired
                if Utc::now() > entry.expires_at {
                    // Remove expired entry
                    let _ = fs::remove_file(&cache_path).await;
                    return Ok(None);
                }

                // Convert cached response back to Response
                let response = self.cached_response_to_response(entry.response)?;
                Ok(Some(response))
            }
            Err(_) => {
                // Cache entry is corrupted, remove it
                let _ = fs::remove_file(&cache_path).await;
                Ok(None)
            }
        }
    }

    /// Store response in cache
    pub async fn store_response(&self, request: &Request, response: &Response) -> Result<()> {
        if !self.config.enabled || !response.is_cacheable() {
            return Ok(());
        }

        let cache_key = request.cache_key();
        let cache_path = self.get_cache_path(&cache_key);

        // Calculate TTL for this response
        let ttl = response.cache_ttl(Duration::from_secs(self.config.response_ttl));
        let now = Utc::now();
        let expires_at =
            now + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::seconds(3600));

        // Convert response to cached format
        let cached_response = self.response_to_cached_response(response)?;
        let body_size = cached_response.body.len() as u64;

        let cache_entry = CacheEntry {
            request_key: cache_key,
            response: cached_response,
            created_at: now,
            expires_at,
            size_bytes: body_size,
        };

        // Check cache size limits
        if body_size > self.config.max_size {
            tracing::warn!("Response too large to cache: {} bytes", body_size);
            return Ok(());
        }

        // Serialize and store
        let serialized = bincode::serialize(&cache_entry)
            .map_err(|e| HttpCliError::cache(format!("Serialization error: {}", e)))?;

        fs::write(&cache_path, serialized).await?;

        // Update cache statistics
        self.update_cache_stats().await?;

        Ok(())
    }

    /// Cache DNS resolution result
    pub fn cache_dns(&mut self, hostname: &str, addresses: Vec<std::net::IpAddr>) {
        if !self.config.enabled {
            return;
        }

        let expires_at = SystemTime::now() + Duration::from_secs(self.config.dns_ttl);

        self.dns_cache.insert(
            hostname.to_string(),
            DnsCacheEntry {
                addresses,
                expires_at,
            },
        );
    }

    /// Get cached DNS resolution result
    pub fn get_dns(&mut self, hostname: &str) -> Option<Vec<std::net::IpAddr>> {
        if !self.config.enabled {
            return None;
        }

        if let Some(entry) = self.dns_cache.get(hostname) {
            if SystemTime::now() < entry.expires_at {
                return Some(entry.addresses.clone());
            } else {
                // Entry expired, remove it
                self.dns_cache.remove(hostname);
            }
        }

        None
    }

    /// Clean up expired cache entries
    pub async fn cleanup_expired(&self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let mut entries = fs::read_dir(&self.config.directory).await?;
        let now = Utc::now();

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            if path.is_file() && path.extension().map(|ext| ext == "cache").unwrap_or(false) {
                match self.load_cache_entry(&path).await {
                    Ok(cache_entry) => {
                        if now > cache_entry.expires_at {
                            let _ = fs::remove_file(&path).await;
                            tracing::debug!("Removed expired cache entry: {}", path.display());
                        }
                    }
                    Err(_) => {
                        // Corrupted cache entry, remove it
                        let _ = fs::remove_file(&path).await;
                        tracing::debug!("Removed corrupted cache entry: {}", path.display());
                    }
                }
            }
        }

        Ok(())
    }

    /// Get cache statistics
    pub async fn get_stats(&self) -> Result<CacheStats> {
        if !self.config.enabled {
            return Ok(CacheStats::default());
        }

        let mut entries = fs::read_dir(&self.config.directory).await?;
        let mut total_entries = 0;
        let mut total_size = 0;
        let mut expired_entries = 0;
        let now = Utc::now();

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            if path.is_file() && path.extension().map(|ext| ext == "cache").unwrap_or(false) {
                total_entries += 1;

                if let Ok(metadata) = fs::metadata(&path).await {
                    total_size += metadata.len();
                }

                if let Ok(cache_entry) = self.load_cache_entry(&path).await {
                    if now > cache_entry.expires_at {
                        expired_entries += 1;
                    }
                }
            }
        }

        Ok(CacheStats {
            total_entries,
            total_size,
            expired_entries,
            dns_entries: self.dns_cache.len(),
            directory: self.config.directory.clone(),
        })
    }

    /// Clear all cache entries
    pub async fn clear(&self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let mut entries = fs::read_dir(&self.config.directory).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_file() {
                fs::remove_file(&path).await?;
            }
        }

        tracing::info!("Cache cleared");
        Ok(())
    }

    fn get_cache_path(&self, cache_key: &str) -> PathBuf {
        self.config.directory.join(format!("{}.cache", cache_key))
    }

    async fn load_cache_entry(&self, path: &Path) -> Result<CacheEntry> {
        let data = fs::read(path).await?;
        bincode::deserialize(&data)
            .map_err(|e| HttpCliError::cache(format!("Deserialization error: {}", e)))
    }

    fn response_to_cached_response(&self, response: &Response) -> Result<CachedResponse> {
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.to_string(),
                    value.to_str().unwrap_or("<invalid>").to_string(),
                )
            })
            .collect();

        Ok(CachedResponse {
            status: response.status().as_u16(),
            headers,
            body: response.body().to_vec(),
            duration_ms: response.duration().as_millis() as u64,
            version: format!("{:?}", response.version()),
        })
    }

    fn cached_response_to_response(&self, cached: CachedResponse) -> Result<Response> {
        use bytes::Bytes;
        use hyper::{HeaderMap, StatusCode, Version};

        let status = StatusCode::from_u16(cached.status)
            .map_err(|_| HttpCliError::cache("Invalid status code in cache".to_string()))?;

        let mut headers = HeaderMap::new();
        for (name, value) in cached.headers {
            if let (Ok(header_name), Ok(header_value)) = (
                name.parse::<hyper::header::HeaderName>(),
                value.parse::<hyper::header::HeaderValue>(),
            ) {
                headers.insert(header_name, header_value);
            }
        }

        let version = match cached.version.as_str() {
            "HTTP_09" => Version::HTTP_09,
            "HTTP_10" => Version::HTTP_10,
            "HTTP_11" => Version::HTTP_11,
            "HTTP_2" => Version::HTTP_2,
            "HTTP_3" => Version::HTTP_3,
            _ => Version::HTTP_11,
        };

        let duration = Duration::from_millis(cached.duration_ms);
        let body = Bytes::from(cached.body);

        Ok(Response::new(status, headers, body, duration, version))
    }

    async fn update_cache_stats(&self) -> Result<()> {
        // This could be implemented to maintain cache statistics
        // For now, we'll just ensure the cache doesn't exceed size limits

        let stats = self.get_stats().await?;
        if stats.total_size > self.config.max_size {
            tracing::warn!("Cache size limit exceeded, cleaning up old entries");
            // TODO: Implement LRU eviction policy
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub total_entries: usize,
    pub total_size: u64,
    pub expired_entries: usize,
    pub dns_entries: usize,
    pub directory: PathBuf,
}

impl CacheStats {
    pub fn display(&self) {
        println!("Cache Statistics:");
        println!("  Directory: {}", self.directory.display());
        println!("  Total entries: {}", self.total_entries);
        println!(
            "  Total size: {} bytes ({:.2} MB)",
            self.total_size,
            self.total_size as f64 / 1024.0 / 1024.0
        );
        println!("  Expired entries: {}", self.expired_entries);
        println!("  DNS entries: {}", self.dns_entries);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn create_test_cache() -> (Cache, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let config = CacheConfig {
            enabled: true,
            directory: temp_dir.path().to_path_buf(),
            dns_ttl: 300,
            response_ttl: 3600,
            tls_session_ttl: 86400,
            max_size: 10 * 1024 * 1024, // 10MB
        };

        let cache = Cache::new(&config).await.unwrap();
        (cache, temp_dir)
    }

    #[tokio::test]
    async fn test_cache_creation() {
        let (_cache, _temp_dir) = create_test_cache().await;
        // Cache creation should succeed
    }

    #[tokio::test]
    async fn test_dns_cache() {
        let (mut cache, _temp_dir) = create_test_cache().await;

        let hostname = "example.com";
        let addresses = vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            93, 184, 216, 34,
        ))];

        // Cache should be empty initially
        assert!(cache.get_dns(hostname).is_none());

        // Cache DNS resolution
        cache.cache_dns(hostname, addresses.clone());

        // Should now return cached result
        assert_eq!(cache.get_dns(hostname), Some(addresses));
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let (cache, _temp_dir) = create_test_cache().await;
        let stats = cache.get_stats().await.unwrap();

        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.total_size, 0);
    }
}

