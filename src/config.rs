use crate::cli::Cli;
use crate::error::{HttpCliError, Result};
use dirs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub client: ClientConfig,
    pub tls: TlsConfig,
    pub cache: CacheConfig,
    pub output: OutputConfig,
    pub auth: AuthConfig,
    pub variables: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub timeout: u64,
    pub connect_timeout: u64,
    pub follow_redirects: bool,
    pub max_redirects: u32,
    pub user_agent: String,
    pub compress: bool,
    pub http_version: String,
    pub max_connections: usize,
    pub pool_idle_timeout: u64,
    pub pool_max_idle_per_host: usize,
    pub max_request_body_size: u64,
    pub max_response_body_size: u64,
    pub max_header_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub verify: bool,
    pub ca_cert: Option<PathBuf>,
    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
    pub min_version: String,
    pub max_version: String,
    pub ciphers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub enabled: bool,
    pub directory: PathBuf,
    pub dns_ttl: u64,
    pub response_ttl: u64,
    pub tls_session_ttl: u64,
    pub max_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub format: String,
    pub highlight: bool,
    pub theme: String,
    pub pager: bool,
    pub colors: bool,
    pub show_headers: bool,
    pub show_timing: bool,
    pub show_meta: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub store_tokens: bool,
    pub keychain_service: String,
    pub profiles: HashMap<String, AuthProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthProfile {
    pub auth_type: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>,
    pub token_type: Option<String>,
    pub headers: HashMap<String, String>,
}

impl Default for Config {
    fn default() -> Self {
        let cache_dir = dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from(".cache"))
            .join("httpcli");

        Self {
            client: ClientConfig {
                timeout: 30,
                connect_timeout: 10,
                follow_redirects: true,
                max_redirects: 10,
                user_agent: format!("httpcli/{}", env!("CARGO_PKG_VERSION")),
                compress: true,
                http_version: "2".to_string(),
                max_connections: 100,
                pool_idle_timeout: 90,
                pool_max_idle_per_host: 10,
                max_request_body_size: 10 * 1024 * 1024, // 10MB
                max_response_body_size: 100 * 1024 * 1024, // 100MB
                max_header_size: 8192, // 8KB
            },
            tls: TlsConfig {
                verify: true,
                ca_cert: None,
                client_cert: None,
                client_key: None,
                min_version: "1.2".to_string(),
                max_version: "1.3".to_string(),
                ciphers: vec![],
            },
            cache: CacheConfig {
                enabled: true,
                directory: cache_dir,
                dns_ttl: 300,
                response_ttl: 3600,
                tls_session_ttl: 86400,
                max_size: 100 * 1024 * 1024, // 100MB
            },
            output: OutputConfig {
                format: "pretty".to_string(),
                highlight: true,
                theme: "base16-ocean.dark".to_string(),
                pager: false,
                colors: true,
                show_headers: false,
                show_timing: false,
                show_meta: false,
            },
            auth: AuthConfig {
                store_tokens: true,
                keychain_service: "httpcli".to_string(),
                profiles: HashMap::new(),
            },
            variables: HashMap::new(),
        }
    }
}

impl Config {
    pub fn load(cli: &Cli) -> Result<Self> {
        let mut config = Self::default();

        // Load from configuration file if specified or found
        if let Some(config_path) = &cli.config {
            config = Self::load_from_file(config_path)?;
        } else if let Some(default_config) = Self::find_default_config() {
            if let Ok(file_config) = Self::load_from_file(&default_config) {
                config = file_config;
            }
        }

        // Load environment variables
        if let Some(env_file) = &cli.env_file {
            dotenv::from_path(env_file).ok();
        } else {
            dotenv::dotenv().ok();
        }

        // Override with CLI arguments
        config.apply_cli_overrides(cli)?;

        Ok(config)
    }

    fn load_from_file(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;

        match path.extension().and_then(|s| s.to_str()) {
            Some("toml") => toml::from_str(&content)
                .map_err(|e| HttpCliError::Config(format!("Invalid TOML config: {}", e))),
            Some("yaml") | Some("yml") => serde_yaml::from_str(&content)
                .map_err(|e| HttpCliError::Config(format!("Invalid YAML config: {}", e))),
            Some("json") => serde_json::from_str(&content)
                .map_err(|e| HttpCliError::Config(format!("Invalid JSON config: {}", e))),
            _ => Err(HttpCliError::Config(
                "Unsupported config file format. Use .toml, .yaml, or .json".to_string(),
            )),
        }
    }

    fn find_default_config() -> Option<PathBuf> {
        let possible_paths = [
            "httpcli.toml",
            "httpcli.yaml",
            "httpcli.yml",
            "httpcli.json",
            ".httpcli.toml",
            ".httpcli.yaml",
            ".httpcli.yml",
            ".httpcli.json",
        ];

        for path_str in &possible_paths {
            let path = PathBuf::from(path_str);
            if path.exists() {
                return Some(path);
            }
        }

        // Check in home directory
        if let Some(home_dir) = dirs::home_dir() {
            for path_str in &possible_paths {
                let path = home_dir.join(path_str);
                if path.exists() {
                    return Some(path);
                }
            }

            // Check in config directory
            if let Some(config_dir) = dirs::config_dir() {
                let httpcli_config_dir = config_dir.join("httpcli");
                for path_str in &["config.toml", "config.yaml", "config.yml", "config.json"] {
                    let path = httpcli_config_dir.join(path_str);
                    if path.exists() {
                        return Some(path);
                    }
                }
            }
        }

        None
    }

    fn apply_cli_overrides(&mut self, cli: &Cli) -> Result<()> {
        // Client configuration overrides
        if cli.timeout > 0 {
            self.client.timeout = cli.timeout;
        }
        if cli.connect_timeout > 0 {
            self.client.connect_timeout = cli.connect_timeout;
        }
        if cli.follow_redirects {
            self.client.follow_redirects = true;
        }
        self.client.max_redirects = cli.max_redirects;

        if let Some(ref user_agent) = cli.user_agent {
            self.client.user_agent = user_agent.clone();
        }

        if cli.compress {
            self.client.compress = true;
        }

        if let Some(ref http_version) = cli.http_version {
            self.client.http_version = match http_version {
                crate::cli::HttpVersion::Http11 => "1.1".to_string(),
                crate::cli::HttpVersion::Http2 => "2".to_string(),
            };
        }

        // TLS configuration overrides
        if cli.insecure {
            self.tls.verify = false;
        }

        if let Some(ref ca_cert) = cli.ca_cert {
            self.tls.ca_cert = Some(ca_cert.clone());
        }

        if let Some(ref cert) = cli.cert {
            self.tls.client_cert = Some(cert.clone());
        }

        if let Some(ref key) = cli.key {
            self.tls.client_key = Some(key.clone());
        }

        // Output configuration overrides
        self.output.format = match cli.output {
            crate::cli::OutputFormat::Pretty => "pretty".to_string(),
            crate::cli::OutputFormat::Body => "body".to_string(),
            crate::cli::OutputFormat::Json => "json".to_string(),
            crate::cli::OutputFormat::Headers => "headers".to_string(),
            crate::cli::OutputFormat::Verbose => "verbose".to_string(),
        };

        self.output.highlight = cli.highlight;
        self.output.theme = cli.theme.clone();

        if cli.show_headers {
            self.output.show_headers = true;
        }

        if cli.show_timing {
            self.output.show_timing = true;
        }

        // Variables from CLI
        let cli_vars = cli.parse_variables();
        self.variables.extend(cli_vars);

        Ok(())
    }

    pub fn save_to_file(&self, path: &PathBuf) -> Result<()> {
        let content = match path.extension().and_then(|s| s.to_str()) {
            Some("toml") => toml::to_string_pretty(self)
                .map_err(|e| HttpCliError::Config(format!("Failed to serialize TOML: {}", e)))?,
            Some("yaml") | Some("yml") => serde_yaml::to_string(self)
                .map_err(|e| HttpCliError::Config(format!("Failed to serialize YAML: {}", e)))?,
            Some("json") => serde_json::to_string_pretty(self)
                .map_err(|e| HttpCliError::Config(format!("Failed to serialize JSON: {}", e)))?,
            _ => {
                return Err(HttpCliError::Config(
                    "Unsupported config file format".to_string(),
                ))
            }
        };

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(path, content)?;
        Ok(())
    }

    pub fn init_default_config() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| HttpCliError::Config("Could not find config directory".to_string()))?
            .join("httpcli");

        std::fs::create_dir_all(&config_dir)?;

        let config_path = config_dir.join("config.toml");
        let default_config = Self::default();
        default_config.save_to_file(&config_path)?;

        Ok(config_path)
    }
}

