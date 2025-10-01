use crate::config::OutputConfig;
use crate::error::{HttpCliError, Result};
use crate::syntax::SyntaxHighlighter;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use hyper::{HeaderMap, StatusCode, Version};
use mime::Mime;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Response {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
    duration: Duration,
    version: Version,
    timestamp: DateTime<Utc>,
}

impl Response {
    pub fn new(
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
        duration: Duration,
        version: Version,
    ) -> Self {
        Self {
            status,
            headers,
            body,
            duration,
            version,
            timestamp: Utc::now(),
        }
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn body(&self) -> &Bytes {
        &self.body
    }

    pub fn duration(&self) -> Duration {
        self.duration
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }

    pub fn body_as_string(&self) -> Result<String> {
        String::from_utf8(self.body.to_vec())
            .map_err(|e| HttpCliError::Generic(format!("Invalid UTF-8 in response body: {}", e)))
    }

    pub fn content_type(&self) -> Option<Mime> {
        self.headers
            .get("content-type")
            .and_then(|ct| ct.to_str().ok())
            .and_then(|ct| ct.parse().ok())
    }

    pub fn content_length(&self) -> Option<u64> {
        self.headers
            .get("content-length")
            .and_then(|cl| cl.to_str().ok())
            .and_then(|cl| cl.parse().ok())
    }

    pub fn is_json(&self) -> bool {
        self.content_type()
            .map(|ct| ct.type_() == "application" && ct.subtype() == "json")
            .unwrap_or(false)
    }

    pub fn is_xml(&self) -> bool {
        self.content_type()
            .map(|ct| {
                (ct.type_() == "application" && ct.subtype() == "xml")
                    || (ct.type_() == "text" && ct.subtype() == "xml")
            })
            .unwrap_or(false)
    }

    pub fn is_html(&self) -> bool {
        self.content_type()
            .map(|ct| ct.type_() == "text" && ct.subtype() == "html")
            .unwrap_or(false)
    }

    pub fn is_text(&self) -> bool {
        self.content_type()
            .map(|ct| ct.type_() == "text")
            .unwrap_or(false)
    }

    pub fn display_headers(&self) {
        println!("{} {}", self.version_string(), self.status);
        for (name, value) in &self.headers {
            println!("{}: {}", name, value.to_str().unwrap_or("<invalid>"));
        }
    }

    pub fn display_body(&self, config: &OutputConfig) -> Result<()> {
        let body_text = self.body_as_string()?;

        if config.highlight {
            let highlighter = SyntaxHighlighter::new(&config.theme)?;
            let highlighted = highlighter.highlight(&body_text, self.detect_language())?;
            print!("{}", highlighted);
        } else {
            print!("{}", body_text);
        }

        Ok(())
    }

    pub fn display_json(&self, config: &OutputConfig) -> Result<()> {
        let body_text = self.body_as_string()?;

        if self.is_json() {
            // Pretty print JSON
            match serde_json::from_str::<serde_json::Value>(&body_text) {
                Ok(json) => {
                    let pretty = serde_json::to_string_pretty(&json)?;
                    if config.highlight {
                        let highlighter = SyntaxHighlighter::new(&config.theme)?;
                        let highlighted = highlighter.highlight(&pretty, "json")?;
                        print!("{}", highlighted);
                    } else {
                        print!("{}", pretty);
                    }
                }
                Err(_) => {
                    // Not valid JSON, display as-is
                    print!("{}", body_text);
                }
            }
        } else {
            // Not JSON, display with appropriate highlighting
            self.display_body(config)?;
        }

        Ok(())
    }

    pub fn display_verbose(&self, config: &OutputConfig, total_duration: Duration) -> Result<()> {
        // Request/Response line
        println!("{} {}", self.version_string(), self.status);

        // Headers
        for (name, value) in &self.headers {
            println!("{}: {}", name, value.to_str().unwrap_or("<invalid>"));
        }

        println!(); // Empty line before body

        // Body
        self.display_body(config)?;

        println!(); // Empty line before timing

        // Timing information
        println!(
            "Response Time: {:.2}ms",
            total_duration.as_secs_f64() * 1000.0
        );
        println!("Content Length: {} bytes", self.body.len());

        if let Some(content_type) = self.content_type() {
            println!("Content Type: {}", content_type);
        }

        Ok(())
    }

    pub fn display_pretty(&self, config: &OutputConfig, total_duration: Duration) -> Result<()> {
        // Status line with colors
        self.print_status_line(config);

        // Headers if requested
        if config.show_headers {
            println!();
            for (name, value) in &self.headers {
                if config.colors {
                    println!(
                        "\x1b[36m{}\x1b[0m: \x1b[33m{}\x1b[0m",
                        name,
                        value.to_str().unwrap_or("<invalid>")
                    );
                } else {
                    println!("{}: {}", name, value.to_str().unwrap_or("<invalid>"));
                }
            }
        }

        println!(); // Empty line before body

        // Body with syntax highlighting
        if !self.body.is_empty() {
            self.display_body(config)?;
        }

        // Timing information if requested
        if config.show_timing {
            println!();
            if config.colors {
                println!(
                    "\x1b[90mResponse Time: {:.2}ms | Size: {} bytes\x1b[0m",
                    total_duration.as_secs_f64() * 1000.0,
                    self.body.len()
                );
            } else {
                println!(
                    "Response Time: {:.2}ms | Size: {} bytes",
                    total_duration.as_secs_f64() * 1000.0,
                    self.body.len()
                );
            }
        }

        Ok(())
    }

    fn print_status_line(&self, config: &OutputConfig) {
        let status_color = if config.colors {
            match self.status.as_u16() {
                200..=299 => "\x1b[32m", // Green for 2xx
                300..=399 => "\x1b[33m", // Yellow for 3xx
                400..=499 => "\x1b[31m", // Red for 4xx
                500..=599 => "\x1b[35m", // Magenta for 5xx
                _ => "\x1b[37m",         // White for others
            }
        } else {
            ""
        };

        let reset_color = if config.colors { "\x1b[0m" } else { "" };

        println!(
            "{}{} {}{}",
            status_color,
            self.status.as_u16(),
            self.status.canonical_reason().unwrap_or("Unknown"),
            reset_color
        );
    }

    fn version_string(&self) -> &'static str {
        match self.version {
            Version::HTTP_09 => "HTTP/0.9",
            Version::HTTP_10 => "HTTP/1.0",
            Version::HTTP_11 => "HTTP/1.1",
            Version::HTTP_2 => "HTTP/2",
            Version::HTTP_3 => "HTTP/3",
            _ => "HTTP/?",
        }
    }

    fn detect_language(&self) -> &str {
        // Detect language based on content type
        if let Some(content_type) = self.content_type() {
            match (
                content_type.type_().as_str(),
                content_type.subtype().as_str(),
            ) {
                ("application", "json") => "json",
                ("application", "xml") | ("text", "xml") => "xml",
                ("text", "html") => "html",
                ("text", "css") => "css",
                ("text", "javascript") | ("application", "javascript") => "javascript",
                ("text", "yaml") | ("application", "yaml") => "yaml",
                ("text", "toml") | ("application", "toml") => "toml",
                ("text", "markdown") => "markdown",
                ("text", "plain") => "text",
                _ => "text",
            }
        } else {
            // Try to detect based on content
            let body_text = self.body_as_string().unwrap_or_default();
            let trimmed = body_text.trim();

            if trimmed.starts_with('{') && trimmed.ends_with('}') {
                "json"
            } else if trimmed.starts_with('<') && trimmed.ends_with('>') {
                if trimmed.contains("<!DOCTYPE html") || trimmed.contains("<html") {
                    "html"
                } else {
                    "xml"
                }
            } else {
                "text"
            }
        }
    }

    /// Check if response can be cached based on HTTP semantics
    pub fn is_cacheable(&self) -> bool {
        // Check for cache-control headers
        if let Some(cache_control) = self.headers.get("cache-control") {
            if let Ok(cc_str) = cache_control.to_str() {
                if cc_str.contains("no-cache") || cc_str.contains("no-store") {
                    return false;
                }
            }
        }

        // Check status code
        match self.status.as_u16() {
            200 | 203 | 204 | 206 | 300 | 301 | 404 | 405 | 410 | 414 | 501 => true,
            _ => false,
        }
    }

    /// Get cache TTL from headers or use default
    pub fn cache_ttl(&self, default_ttl: Duration) -> Duration {
        // Check Cache-Control max-age
        if let Some(cache_control) = self.headers.get("cache-control") {
            if let Ok(cc_str) = cache_control.to_str() {
                for directive in cc_str.split(',') {
                    let directive = directive.trim();
                    if directive.starts_with("max-age=") {
                        if let Ok(max_age) = directive[8..].parse::<u64>() {
                            return Duration::from_secs(max_age);
                        }
                    }
                }
            }
        }

        // Check Expires header
        if let Some(expires) = self.headers.get("expires") {
            if let Ok(expires_str) = expires.to_str() {
                if let Ok(expires_time) = chrono::DateTime::parse_from_rfc2822(expires_str) {
                    let now = Utc::now();
                    if expires_time > now {
                        let duration = expires_time.signed_duration_since(now);
                        if let Ok(std_duration) = duration.to_std() {
                            return std_duration;
                        }
                    }
                }
            }
        }

        default_ttl
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{CACHE_CONTROL, CONTENT_TYPE};

    #[test]
    fn test_content_type_detection() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());

        let response = Response::new(
            StatusCode::OK,
            headers,
            Bytes::from("{}"),
            Duration::from_millis(100),
            Version::HTTP_11,
        );

        assert!(response.is_json());
        assert!(!response.is_xml());
    }

    #[test]
    fn test_language_detection() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());

        let response = Response::new(
            StatusCode::OK,
            headers,
            Bytes::from("{}"),
            Duration::from_millis(100),
            Version::HTTP_11,
        );

        assert_eq!(response.detect_language(), "json");
    }

    #[test]
    fn test_cache_control() {
        let mut headers = HeaderMap::new();
        headers.insert(CACHE_CONTROL, "no-cache".parse().unwrap());

        let response = Response::new(
            StatusCode::OK,
            headers,
            Bytes::from("test"),
            Duration::from_millis(100),
            Version::HTTP_11,
        );

        assert!(!response.is_cacheable());
    }
}

