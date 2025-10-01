use clap::{Parser, Subcommand, ValueEnum};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "httpcli",
    version = env!("CARGO_PKG_VERSION"),
    about = "A high-performance HTTP CLI tool with .http file support and syntax highlighting",
    author = "Adrian Najera",
    long_about = r#"
httpcli is a blazing-fast HTTP client designed for developers and API testing.
It supports .http files, advanced authentication, syntax highlighting, and 
performance optimization features for production use.

Examples:
  httpcli GET https://api.example.com/users
  httpcli POST https://api.example.com/users -d '{"name": "John"}'
  httpcli --file requests.http
  httpcli --benchmark -n 1000 GET https://api.example.com/health
"#
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// HTTP method (GET, POST, PUT, DELETE, etc.)
    #[arg(value_enum, global = true)]
    pub method: Option<HttpMethod>,

    /// URL to request
    #[arg(global = true)]
    pub url: Option<String>,

    /// Request headers (can be used multiple times)
    #[arg(short = 'H', long = "header", global = true, action = clap::ArgAction::Append)]
    pub headers: Vec<String>,

    /// Request body data
    #[arg(short = 'd', long = "data", global = true)]
    pub data: Option<String>,

    /// Read request body from file
    #[arg(long = "data-binary", global = true)]
    pub data_binary: Option<PathBuf>,

    /// Content-Type header
    #[arg(short = 'c', long = "content-type", global = true)]
    pub content_type: Option<String>,

    /// Execute requests from .http file
    #[arg(short = 'f', long = "file", global = true)]
    pub file: Option<PathBuf>,

    #[arg(long = "request-name", global = true)]
    pub request_name: Option<String>,

    #[arg(long = "request-index", global = true)]
    pub request_index: Option<usize>,

    /// Output format
    #[arg(
        short = 'o',
        long = "output",
        value_enum,
        global = true,
        default_value = "pretty"
    )]
    pub output: OutputFormat,

    /// Verbose output (can be used multiple times for more verbosity)
    #[arg(short = 'v', long = "verbose", global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Silent mode (no output except response body)
    #[arg(short = 's', long = "silent", global = true)]
    pub silent: bool,

    /// Follow redirects
    #[arg(long = "follow", global = true)]
    pub follow_redirects: bool,

    /// Maximum number of redirects to follow
    #[arg(long = "max-redirects", global = true, default_value = "10")]
    pub max_redirects: u32,

    /// Request timeout in seconds
    #[arg(short = 't', long = "timeout", global = true, default_value = "30")]
    pub timeout: u64,

    /// Connection timeout in seconds
    #[arg(long = "connect-timeout", global = true, default_value = "10")]
    pub connect_timeout: u64,

    /// User agent string
    #[arg(long = "user-agent", global = true)]
    pub user_agent: Option<String>,

    /// Basic authentication (username:password)
    #[arg(short = 'a', long = "auth", global = true)]
    pub auth: Option<String>,

    /// Bearer token authentication
    #[arg(long = "token", global = true)]
    pub token: Option<String>,

    /// Custom CA certificate file
    #[arg(long = "cacert", global = true)]
    pub ca_cert: Option<PathBuf>,

    /// Client certificate file
    #[arg(long = "cert", global = true)]
    pub cert: Option<PathBuf>,

    /// Client private key file
    #[arg(long = "key", global = true)]
    pub key: Option<PathBuf>,

    /// Disable TLS verification
    #[arg(long = "insecure", global = true)]
    pub insecure: bool,

    /// HTTP version to use
    #[arg(long = "http-version", value_enum, global = true)]
    pub http_version: Option<HttpVersion>,

    /// Enable compression
    #[arg(long = "compress", global = true)]
    pub compress: bool,

    /// Proxy URL
    #[arg(long = "proxy", global = true)]
    pub proxy: Option<String>,

    /// Configuration file path
    #[arg(long = "config", global = true)]
    pub config: Option<PathBuf>,

    /// Environment variables file (.env)
    #[arg(long = "env-file", global = true)]
    pub env_file: Option<PathBuf>,

    /// Variables for .http file substitution
    #[arg(long = "var", global = true, action = clap::ArgAction::Append)]
    pub variables: Vec<String>,

    /// Save response to file
    #[arg(long = "save", global = true)]
    pub save: Option<PathBuf>,

    /// Pretty print JSON responses
    #[arg(long = "json", global = true)]
    pub json: bool,

    /// Show response headers
    #[arg(long = "headers", global = true)]
    pub show_headers: bool,

    /// Show timing information
    #[arg(long = "timing", global = true)]
    pub show_timing: bool,

    /// Enable syntax highlighting
    #[arg(long = "highlight", global = true, default_value = "true")]
    pub highlight: bool,

    /// Color theme for syntax highlighting
    #[arg(long = "theme", global = true, default_value = "base16-ocean.dark")]
    pub theme: String,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Send HTTP GET request
    Get {
        /// URL to request
        url: String,
    },
    /// Send HTTP POST request
    Post {
        /// URL to request
        url: String,
    },
    /// Send HTTP PUT request
    Put {
        /// URL to request
        url: String,
    },
    /// Send HTTP DELETE request
    Delete {
        /// URL to request
        url: String,
    },
    /// Send HTTP PATCH request
    Patch {
        /// URL to request
        url: String,
    },
    /// Send HTTP HEAD request
    Head {
        /// URL to request
        url: String,
    },
    /// Send HTTP OPTIONS request
    Options {
        /// URL to request
        url: String,
    },
    /// Execute requests from .http file
    File {
        /// Path to .http file
        path: PathBuf,
    },
    /// Run benchmark tests
    Benchmark {
        /// Number of requests
        #[arg(short = 'n', long = "requests", default_value = "100")]
        requests: u32,

        /// Concurrency level
        #[arg(short = 'c', long = "concurrency", default_value = "10")]
        concurrency: u32,

        /// Duration in seconds
        #[arg(short = 'd', long = "duration")]
        duration: Option<u64>,

        /// URL to benchmark
        url: String,
    },
    /// Show configuration
    Config {
        /// Show current configuration
        #[arg(long = "show")]
        show: bool,

        /// Initialize default configuration
        #[arg(long = "init")]
        init: bool,
    },
}

#[derive(ValueEnum, Debug, Clone)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
}

impl HttpMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Head => "HEAD",
            HttpMethod::Options => "OPTIONS",
        }
    }
}

#[derive(ValueEnum, Debug, Clone)]
pub enum OutputFormat {
    /// Pretty-printed with colors and formatting
    Pretty,
    /// Raw response body only
    Body,
    /// JSON formatted output
    Json,
    /// Headers only
    Headers,
    /// Verbose output with request/response details
    Verbose,
}

#[derive(ValueEnum, Debug, Clone)]
pub enum HttpVersion {
    #[clap(name = "1.1")]
    Http11,
    #[clap(name = "2")]
    Http2,
}

impl Cli {
    pub fn get_method(&self) -> &str {
        if let Some(ref command) = self.command {
            match command {
                Commands::Get { .. } => "GET",
                Commands::Post { .. } => "POST",
                Commands::Put { .. } => "PUT",
                Commands::Delete { .. } => "DELETE",
                Commands::Patch { .. } => "PATCH",
                Commands::Head { .. } => "HEAD",
                Commands::Options { .. } => "OPTIONS",
                _ => self.method.as_ref().map(|m| m.as_str()).unwrap_or("GET"),
            }
        } else {
            self.method.as_ref().map(|m| m.as_str()).unwrap_or("GET")
        }
    }

    pub fn get_url(&self) -> Option<&str> {
        if let Some(ref command) = self.command {
            match command {
                Commands::Get { url }
                | Commands::Post { url }
                | Commands::Put { url }
                | Commands::Delete { url }
                | Commands::Patch { url }
                | Commands::Head { url }
                | Commands::Options { url }
                | Commands::Benchmark { url, .. } => Some(url),
                _ => self.url.as_deref(),
            }
        } else {
            self.url.as_deref()
        }
    }

    pub fn parse_variables(&self) -> HashMap<String, String> {
        let mut vars = HashMap::new();
        for var in &self.variables {
            if let Some((key, value)) = var.split_once('=') {
                vars.insert(key.to_string(), value.to_string());
            }
        }
        vars
    }
}
