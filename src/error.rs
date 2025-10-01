use thiserror::Error;

pub type Result<T> = std::result::Result<T, HttpCliError>;

#[derive(Error, Debug)]
pub enum HttpCliError {
    #[error("HTTP request failed: {0}")]
    HttpRequest(#[from] hyper::Error),

    #[error("HTTP client error: {0}")]
    HttpClient(#[from] hyper_util::client::legacy::Error),

    #[error("Invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),

    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("YAML serialization error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("TOML serialization error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("HTTP file parsing error: {0}")]
    HttpFileParser(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("DNS resolution failed: {0}")]
    DnsResolution(String),

    #[error("Connection timeout")]
    Timeout,

    #[error("Request cancelled")]
    Cancelled,

    #[error("Invalid header: {0}")]
    InvalidHeader(String),

    #[error("Syntax highlighting error: {0}")]
    SyntaxHighlight(String),

    #[error("Cache error: {0}")]
    Cache(String),

    #[error("Generic error: {0}")]
    Generic(String),
}

impl HttpCliError {
    pub fn http_file_parser(msg: impl Into<String>) -> Self {
        Self::HttpFileParser(msg.into())
    }

    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    pub fn auth(msg: impl Into<String>) -> Self {
        Self::Auth(msg.into())
    }

    pub fn dns_resolution(msg: impl Into<String>) -> Self {
        Self::DnsResolution(msg.into())
    }

    pub fn invalid_header(msg: impl Into<String>) -> Self {
        Self::InvalidHeader(msg.into())
    }

    pub fn syntax_highlight(msg: impl Into<String>) -> Self {
        Self::SyntaxHighlight(msg.into())
    }

    pub fn cache(msg: impl Into<String>) -> Self {
        Self::Cache(msg.into())
    }

    pub fn generic(msg: impl Into<String>) -> Self {
        Self::Generic(msg.into())
    }
}

