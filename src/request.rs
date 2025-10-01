use crate::error::{HttpCliError, Result};
use bytes::Bytes;
use std::collections::HashMap;
use std::time::Duration;
use url::Url;

#[derive(Debug, Clone)]
pub struct Request {
    method: String,
    url: Url,
    headers: HashMap<String, String>,
    body: Option<Bytes>,
    timeout: Duration,
}

impl Request {
    pub fn builder() -> RequestBuilder {
        RequestBuilder::new()
    }

    pub fn method(&self) -> &str {
        &self.method
    }

    pub fn url(&self) -> &str {
        self.url.as_str()
    }

    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    pub fn body(&self) -> Option<&Bytes> {
        self.body.as_ref()
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Generate a cache key for this request
    pub fn cache_key(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.method.hash(&mut hasher);
        self.url.as_str().hash(&mut hasher);

        // Include relevant headers in cache key
        let mut sorted_headers: Vec<_> = self.headers.iter().collect();
        sorted_headers.sort_by(|a, b| a.0.cmp(b.0));
        for (k, v) in sorted_headers {
            k.hash(&mut hasher);
            v.hash(&mut hasher);
        }

        if let Some(ref body) = self.body {
            body.hash(&mut hasher);
        }

        format!("{:x}", hasher.finish())
    }
}

pub struct RequestBuilder {
    method: Option<String>,
    url: Option<String>,
    headers: HashMap<String, String>,
    body: Option<Bytes>,
    timeout: Duration,
}

impl RequestBuilder {
    pub fn new() -> Self {
        Self {
            method: None,
            url: None,
            headers: HashMap::new(),
            body: None,
            timeout: Duration::from_secs(30),
        }
    }

    pub fn method(mut self, method: &str) -> Self {
        self.method = Some(method.to_uppercase());
        self
    }

    pub fn url(mut self, url: &str) -> Self {
        self.url = Some(url.to_string());
        self
    }

    pub fn headers(mut self, headers: &[String]) -> Self {
        for header in headers {
            if let Some((name, value)) = header.split_once(':') {
                self.headers
                    .insert(name.trim().to_string(), value.trim().to_string());
            }
        }
        self
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_string(), value.to_string());
        self
    }

    pub fn body(mut self, body: Option<Bytes>) -> Self {
        self.body = body;
        self
    }

    pub fn content_type(mut self, content_type: Option<&str>) -> Self {
        if let Some(ct) = content_type {
            self.headers
                .insert("Content-Type".to_string(), ct.to_string());
        }
        self
    }

    pub fn user_agent(mut self, user_agent: &str) -> Self {
        self.headers
            .insert("User-Agent".to_string(), user_agent.to_string());
        self
    }

    pub fn auth(mut self, auth: Option<String>) -> Result<Self> {
        if let Some(auth_header) = auth {
            self.headers
                .insert("Authorization".to_string(), auth_header);
        }
        Ok(self)
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn build(self) -> Result<Request> {
        let method = self
            .method
            .ok_or_else(|| HttpCliError::Generic("HTTP method is required".to_string()))?;

        let url_str = self
            .url
            .ok_or_else(|| HttpCliError::Generic("URL is required".to_string()))?;

        let url = Url::parse(&url_str)?;

        // Validate HTTP method
        match method.as_str() {
            "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS" => {}
            _ => {
                return Err(HttpCliError::Generic(format!(
                    "Unsupported HTTP method: {}",
                    method
                )))
            }
        }

        // Set default headers if not provided
        let mut headers = self.headers;

        // Add Content-Length for methods that typically have bodies
        if matches!(method.as_str(), "POST" | "PUT" | "PATCH") && self.body.is_some() {
            if !headers.contains_key("Content-Length") {
                let content_length = self.body.as_ref().map(|b| b.len()).unwrap_or(0);
                headers.insert("Content-Length".to_string(), content_length.to_string());
            }
        }

        // Add Accept header if not present
        if !headers.contains_key("Accept") {
            headers.insert("Accept".to_string(), "*/*".to_string());
        }

        // Add Accept-Encoding for compression
        if !headers.contains_key("Accept-Encoding") {
            headers.insert(
                "Accept-Encoding".to_string(),
                "gzip, deflate, br".to_string(),
            );
        }

        // Add Connection header for keep-alive
        if !headers.contains_key("Connection") {
            headers.insert("Connection".to_string(), "keep-alive".to_string());
        }

        Ok(Request {
            method,
            url,
            headers,
            body: self.body,
            timeout: self.timeout,
        })
    }
}

impl Default for RequestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_builder() {
        let request = Request::builder()
            .method("GET")
            .url("https://api.example.com/users")
            .header("Authorization", "Bearer token123")
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        assert_eq!(request.method(), "GET");
        assert_eq!(request.url(), "https://api.example.com/users");
        assert_eq!(
            request.headers().get("Authorization"),
            Some(&"Bearer token123".to_string())
        );
        assert_eq!(request.timeout(), Duration::from_secs(10));
    }

    #[test]
    fn test_cache_key_generation() {
        let request1 = Request::builder()
            .method("GET")
            .url("https://api.example.com/users")
            .build()
            .unwrap();

        let request2 = Request::builder()
            .method("GET")
            .url("https://api.example.com/users")
            .build()
            .unwrap();

        let request3 = Request::builder()
            .method("POST")
            .url("https://api.example.com/users")
            .build()
            .unwrap();

        assert_eq!(request1.cache_key(), request2.cache_key());
        assert_ne!(request1.cache_key(), request3.cache_key());
    }

    #[test]
    fn test_invalid_method() {
        let result = Request::builder()
            .method("INVALID")
            .url("https://api.example.com")
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_url() {
        let result = Request::builder()
            .method("GET")
            .url("not-a-valid-url")
            .build();

        assert!(result.is_err());
    }
}

