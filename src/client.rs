use crate::cache::Cache;
use crate::cli::{Cli, Commands};
use crate::config::Config;
use crate::error::{HttpCliError, Result};
use crate::request::Request;
use crate::response::Response;
use crate::tls::TlsConnector;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request as HyperRequest};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client as HyperClient};
use hyper_util::rt::TokioExecutor;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{debug, info};

pub struct HttpClient {
    client: HyperClient<HttpsConnector<HttpConnector>, Full<Bytes>>,
    config: Config,
    cache: Option<Cache>,
}

impl HttpClient {
    pub async fn new(config: Config) -> Result<Self> {
        info!("Initializing high-performance HTTP client");

        let tls_config = TlsConnector::new(&config.tls)?;

        let mut http_connector = HttpConnector::new();
        http_connector
            .set_connect_timeout(Some(Duration::from_secs(config.client.connect_timeout)));
        http_connector.set_keepalive(Some(Duration::from_secs(config.client.pool_idle_timeout)));
        http_connector.set_nodelay(true);
        http_connector.set_reuse_address(true);
        http_connector.enforce_http(false);

        let tls_config_arc = tls_config.client_config();
        let tls_config_owned = Arc::try_unwrap(tls_config_arc).unwrap_or_else(|arc| (*arc).clone());
        let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config_owned)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http_connector);

        let client = HyperClient::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(config.client.pool_idle_timeout))
            .pool_max_idle_per_host(config.client.pool_max_idle_per_host)
            .http2_only(false)
            .build(https_connector);

        let cache = if config.cache.enabled {
            Some(Cache::new(&config.cache).await?)
        } else {
            None
        };

        Ok(Self {
            client,
            config,
            cache,
        })
    }

    pub async fn execute(&self, cli: Cli) -> Result<()> {
        match &cli.command {
            Some(Commands::Get { url }) => self.execute_single_request("GET", url, &cli).await,
            Some(Commands::Post { url }) => self.execute_single_request("POST", url, &cli).await,
            Some(Commands::Put { url }) => self.execute_single_request("PUT", url, &cli).await,
            Some(Commands::Delete { url }) => {
                self.execute_single_request("DELETE", url, &cli).await
            }
            Some(Commands::Patch { url }) => self.execute_single_request("PATCH", url, &cli).await,
            Some(Commands::Head { url }) => self.execute_single_request("HEAD", url, &cli).await,
            Some(Commands::Options { url }) => {
                self.execute_single_request("OPTIONS", url, &cli).await
            }
            Some(Commands::File { path }) => self.execute_http_file(path, &cli).await,
            Some(Commands::Benchmark {
                requests,
                concurrency,
                duration,
                url,
            }) => {
                self.execute_benchmark(url, *requests, *concurrency, *duration, &cli)
                    .await
            }
            Some(Commands::Config { show, init }) => self.handle_config_command(*show, *init).await,
            None => {
                if let Some(url) = cli.get_url() {
                    let method = cli.get_method();
                    self.execute_single_request(method, url, &cli).await
                } else if let Some(ref file_path) = cli.file {
                    self.execute_http_file(file_path, &cli).await
                } else {
                    Err(HttpCliError::Config(
                        "No URL or .http file specified".to_string(),
                    ))
                }
            }
        }
    }

    async fn execute_single_request(&self, method: &str, url: &str, cli: &Cli) -> Result<()> {
        let start_time = Instant::now();

        debug!("Executing {} request to {}", method, url);

        // Handle download mode separately
        if cli.download {
            return self.download_file(method, url, cli).await;
        }

        // Determine content type (multipart takes precedence)
        let content_type = if !cli.form.is_empty() {
            let (_body, ct) = self.build_multipart_body(&cli.form).await?;
            Some(ct)
        } else {
            cli.content_type.clone()
        };

        let request = Request::builder()
            .method(method)
            .url(url)
            .headers(&cli.headers)
            .body(self.build_request_body(cli).await?)
            .content_type(content_type.as_deref())
            .user_agent(&self.config.client.user_agent)
            .auth(self.build_auth(cli)?)?
            .timeout(Duration::from_secs(self.config.client.timeout))
            .build()?;

        if let Some(ref cache) = self.cache {
            if let Some(cached_response) = cache.get_response(&request).await? {
                info!("Serving response from cache");
                self.display_response(cached_response, cli, start_time)
                    .await?;
                return Ok(());
            }
        }

        let response = match timeout(
            Duration::from_secs(self.config.client.timeout),
            self.send_request(request.clone()),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => return Err(HttpCliError::Timeout),
        };

        if let Some(ref cache) = self.cache {
            cache.store_response(&request, &response).await?;
        }

        self.display_response(response, cli, start_time).await?;

        Ok(())
    }

    async fn send_request(&self, request: Request) -> Result<Response> {
        let hyper_request = self.build_hyper_request(request)?;

        let start_time = Instant::now();
        let hyper_response = self.client.request(hyper_request).await?;
        let duration = start_time.elapsed();

        let status = hyper_response.status();
        let headers = hyper_response.headers().clone();
        let version = hyper_response.version();

        let body = hyper_response.into_body();
        let body_bytes = body.collect().await?.to_bytes();

        if body_bytes.len() as u64 > self.config.client.max_response_body_size {
            return Err(HttpCliError::Generic(format!(
                "Response body size ({} bytes) exceeds maximum allowed size ({} bytes)",
                body_bytes.len(),
                self.config.client.max_response_body_size
            )));
        }

        let decompressed_bytes = self.decompress_body(&headers, body_bytes)?;

        Ok(Response::new(
            status,
            headers,
            decompressed_bytes,
            duration,
            version,
        ))
    }

    fn build_hyper_request(&self, request: Request) -> Result<HyperRequest<Full<Bytes>>> {
        let method = request
            .method()
            .parse::<Method>()
            .map_err(|_| HttpCliError::Generic("Invalid HTTP method".to_string()))?;

        let mut builder = HyperRequest::builder().method(method).uri(request.url());

        let mut total_header_size = 0u64;
        for (name, value) in request.headers() {
            let header_size = name.len() + value.len() + 4;
            total_header_size += header_size as u64;

            if total_header_size > self.config.client.max_header_size {
                return Err(HttpCliError::Generic(format!(
                    "Total header size ({} bytes) exceeds maximum allowed size ({} bytes)",
                    total_header_size, self.config.client.max_header_size
                )));
            }

            builder = builder.header(name, value);
        }

        let body = if let Some(body_data) = request.body() {
            Full::new(body_data.clone())
        } else {
            Full::new(Bytes::new())
        };

        builder
            .body(body)
            .map_err(|e| HttpCliError::Generic(format!("Failed to build request: {}", e)))
    }

    fn decompress_body(&self, headers: &hyper::HeaderMap, body: Bytes) -> Result<Bytes> {
        if let Some(encoding) = headers.get("content-encoding") {
            match encoding.to_str().unwrap_or("") {
                "gzip" => {
                    use flate2::read::GzDecoder;
                    use std::io::Read;

                    let mut decoder = GzDecoder::new(&body[..]);
                    let mut decompressed = Vec::new();
                    decoder.read_to_end(&mut decompressed).map_err(|e| {
                        HttpCliError::Generic(format!("Gzip decompression failed: {}", e))
                    })?;
                    Ok(Bytes::from(decompressed))
                }
                "deflate" => {
                    use flate2::read::DeflateDecoder;
                    use std::io::Read;

                    let mut decoder = DeflateDecoder::new(&body[..]);
                    let mut decompressed = Vec::new();
                    decoder.read_to_end(&mut decompressed).map_err(|e| {
                        HttpCliError::Generic(format!("Deflate decompression failed: {}", e))
                    })?;
                    Ok(Bytes::from(decompressed))
                }
                "br" => {
                    use brotli::Decompressor;
                    use std::io::Read;

                    let mut decoder = Decompressor::new(&body[..], 4096);
                    let mut decompressed = Vec::new();
                    decoder.read_to_end(&mut decompressed).map_err(|e| {
                        HttpCliError::Generic(format!("Brotli decompression failed: {}", e))
                    })?;
                    Ok(Bytes::from(decompressed))
                }
                _ => Ok(body),
            }
        } else {
            Ok(body)
        }
    }

    async fn build_request_body(&self, cli: &Cli) -> Result<Option<Bytes>> {
        // Check for multipart form data first
        if !cli.form.is_empty() {
            let (body, _content_type) = self.build_multipart_body(&cli.form).await?;
            if body.len() as u64 > self.config.client.max_request_body_size {
                return Err(HttpCliError::Generic(format!(
                    "Request body size ({} bytes) exceeds maximum allowed size ({} bytes)",
                    body.len(),
                    self.config.client.max_request_body_size
                )));
            }
            return Ok(Some(body));
        }

        if let Some(ref data) = cli.data {
            let body_bytes = Bytes::from(data.clone());
            if body_bytes.len() as u64 > self.config.client.max_request_body_size {
                return Err(HttpCliError::Generic(format!(
                    "Request body size ({} bytes) exceeds maximum allowed size ({} bytes)",
                    body_bytes.len(),
                    self.config.client.max_request_body_size
                )));
            }
            Ok(Some(body_bytes))
        } else if let Some(ref file_path) = cli.data_binary {
            let data = tokio::fs::read(file_path).await?;
            if data.len() as u64 > self.config.client.max_request_body_size {
                return Err(HttpCliError::Generic(format!(
                    "Request body size ({} bytes) exceeds maximum allowed size ({} bytes)",
                    data.len(),
                    self.config.client.max_request_body_size
                )));
            }
            Ok(Some(Bytes::from(data)))
        } else {
            Ok(None)
        }
    }

    async fn build_multipart_body(&self, form_fields: &[String]) -> Result<(Bytes, String)> {
        use uuid::Uuid;

        // Generate unique boundary
        let boundary = format!("----httpcli{}", Uuid::new_v4().simple());
        let mut body = Vec::new();

        for field in form_fields {
            if let Some((key, value)) = field.split_once('=') {
                body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());

                if value.starts_with('@') {
                    // File upload: field@path
                    let file_path = &value[1..];
                    let path = std::path::Path::new(file_path);

                    if !path.exists() {
                        return Err(HttpCliError::Generic(format!(
                            "File not found: {}",
                            file_path
                        )));
                    }

                    let filename = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("file");

                    let content = tokio::fs::read(path).await?;

                    // Guess content type from file extension
                    let content_type = mime_guess::from_path(path)
                        .first_or_octet_stream()
                        .to_string();

                    body.extend_from_slice(
                        format!(
                            "Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n",
                            key, filename
                        )
                        .as_bytes(),
                    );
                    body.extend_from_slice(
                        format!("Content-Type: {}\r\n\r\n", content_type).as_bytes(),
                    );
                    body.extend_from_slice(&content);
                    body.extend_from_slice(b"\r\n");
                } else {
                    // Text field
                    body.extend_from_slice(
                        format!("Content-Disposition: form-data; name=\"{}\"\r\n\r\n", key)
                            .as_bytes(),
                    );
                    body.extend_from_slice(value.as_bytes());
                    body.extend_from_slice(b"\r\n");
                }
            }
        }

        // Final boundary
        body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

        let content_type = format!("multipart/form-data; boundary={}", boundary);
        Ok((Bytes::from(body), content_type))
    }

    fn build_auth(&self, cli: &Cli) -> Result<Option<String>> {
        if let Some(ref auth) = cli.auth {
            if auth.contains(':') {
                use base64::Engine;
                let encoded = base64::engine::general_purpose::STANDARD.encode(auth.as_bytes());
                Ok(Some(format!("Basic {}", encoded)))
            } else {
                Err(HttpCliError::Auth(
                    "Invalid basic auth format. Use username:password".to_string(),
                ))
            }
        } else if let Some(ref token) = cli.token {
            Ok(Some(format!("Bearer {}", token)))
        } else {
            Ok(None)
        }
    }

    async fn download_file(&self, method: &str, url: &str, cli: &Cli) -> Result<()> {
        use indicatif::{ProgressBar, ProgressStyle};
        use tokio::io::AsyncWriteExt;

        info!("Download mode activated for {}", url);

        // Determine output path
        let output_path = if let Some(ref path) = cli.output_file {
            path.clone()
        } else {
            // Auto-detect filename from URL
            let url_path = url::Url::parse(url)?.path().to_string();
            let filename = url_path.split('/').last().unwrap_or("download");
            std::path::PathBuf::from(if filename.is_empty() { "download" } else { filename })
        };

        // Check for resume support
        let existing_size = if cli.resume && output_path.exists() {
            tokio::fs::metadata(&output_path).await.ok()
                .map(|m| m.len())
                .unwrap_or(0)
        } else {
            0
        };

        // Build request with optional Range header
        let mut headers = cli.headers.clone();
        if existing_size > 0 {
            headers.push(format!("Range: bytes={}-", existing_size));
            info!("Resuming download from byte {}", existing_size);
        }

        let request = Request::builder()
            .method(method)
            .url(url)
            .headers(&headers)
            .user_agent(&self.config.client.user_agent)
            .auth(self.build_auth(cli)?)?
            .timeout(Duration::from_secs(self.config.client.timeout))
            .build()?;

        let hyper_request = self.build_hyper_request(request)?;
        let mut hyper_response = self.client.request(hyper_request).await?;

        // Handle redirects manually for download mode
        let mut redirect_count = 0;
        let max_redirects = if cli.follow_redirects || self.config.client.follow_redirects {
            self.config.client.max_redirects
        } else {
            0
        };

        while redirect_count < max_redirects {
            let status = hyper_response.status();

            // Check if this is a redirect
            if status.is_redirection() {
                if let Some(location) = hyper_response.headers().get("location") {
                    let location_str = location.to_str()
                        .map_err(|_| HttpCliError::Generic("Invalid redirect location".to_string()))?;

                    // Resolve relative URLs
                    let redirect_url = if location_str.starts_with("http") {
                        location_str.to_string()
                    } else {
                        let base = url::Url::parse(url)?;
                        base.join(location_str)?.to_string()
                    };

                    info!("Following redirect to: {}", redirect_url);
                    redirect_count += 1;

                    // Make new request to redirect location
                    let redirect_request = Request::builder()
                        .method(method)
                        .url(&redirect_url)
                        .headers(&headers)
                        .user_agent(&self.config.client.user_agent)
                        .auth(self.build_auth(cli)?)?
                        .timeout(Duration::from_secs(self.config.client.timeout))
                        .build()?;

                    let redirect_hyper_request = self.build_hyper_request(redirect_request)?;
                    hyper_response = self.client.request(redirect_hyper_request).await?;
                    continue;
                }
            }

            // Not a redirect, break
            break;
        }

        let status = hyper_response.status();
        let headers_map = hyper_response.headers();

        // Check if server supports resume
        if existing_size > 0 && status.as_u16() != 206 {
            if status.as_u16() == 200 {
                info!("Server doesn't support resume, restarting download from beginning");
            } else {
                return Err(HttpCliError::Generic(format!(
                    "Unexpected status code for resume: {}",
                    status
                )));
            }
        }

        // Get content length
        let content_length = headers_map
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let total_size = if status.as_u16() == 206 {
            // Partial content - add existing size
            content_length.map(|len| len + existing_size)
        } else {
            content_length
        };

        let pb = if let Some(size) = total_size {
            let pb = ProgressBar::new(size);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("[{bar:40}] {bytes}/{total_bytes} ({eta})")
                    .expect("Failed to create progress style")
                    .progress_chars("=> "),
            );
            if existing_size > 0 {
                pb.set_position(existing_size);
            }
            Some(pb)
        } else {
            // Unknown size - use spinner
            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner} {bytes} downloaded")
                    .expect("Failed to create spinner style"),
            );
            Some(pb)
        };

        // Open file for writing
        let mut file = if existing_size > 0 && status.as_u16() == 206 {
            // Append mode for resume
            tokio::fs::OpenOptions::new()
                .append(true)
                .open(&output_path)
                .await?
        } else {
            // Create new file
            tokio::fs::File::create(&output_path).await?
        };

        // Stream response body to file
        let mut body = hyper_response.into_body();
        let mut downloaded = existing_size;

        while let Some(chunk) = body.frame().await {
            let frame = chunk.map_err(|e| HttpCliError::Generic(format!("Stream error: {}", e)))?;

            if let Ok(data) = frame.into_data() {
                file.write_all(&data).await?;
                downloaded += data.len() as u64;

                if let Some(ref pb) = pb {
                    pb.set_position(downloaded);
                }
            }
        }

        file.flush().await?;

        if let Some(pb) = pb {
            pb.finish_with_message(format!("Downloaded to {}", output_path.display()));
        }

        info!("Download complete: {}", output_path.display());
        println!("Downloaded {} bytes to {}", downloaded, output_path.display());

        Ok(())
    }

    async fn display_response(
        &self,
        response: Response,
        cli: &Cli,
        start_time: Instant,
    ) -> Result<()> {
        if cli.silent {
            print!("{}", response.body_as_string()?);
            return Ok(());
        }

        let total_duration = start_time.elapsed();

        match self.config.output.format.as_str() {
            "headers" => response.display_headers(),
            "body" => response.display_body(&self.config.output)?,
            "json" => response.display_json(&self.config.output)?,
            "verbose" => response.display_verbose(&self.config.output, total_duration)?,
            "pretty" | _ => response.display_pretty(&self.config.output, total_duration)?,
        }

        if let Some(ref save_path) = cli.save {
            tokio::fs::write(save_path, response.body()).await?;
            info!("Response saved to {}", save_path.display());
        }

        Ok(())
    }

    async fn execute_http_file(&self, file_path: &std::path::Path, cli: &Cli) -> Result<()> {
        use crate::http_parser::HttpFileParser;

        info!("Parsing .http file: {}", file_path.display());

        let mut parser = HttpFileParser::new();
        let http_file = parser.parse_file(file_path).await?;

        let requests_to_execute: Vec<_> = if let Some(ref request_name) = cli.request_name {
            http_file
                .requests
                .iter()
                .filter(|req| req.name.as_ref() == Some(request_name))
                .collect()
        } else if let Some(request_index) = cli.request_index {
            if request_index < http_file.requests.len() {
                vec![&http_file.requests[request_index]]
            } else {
                return Err(HttpCliError::Config(format!(
                    "Request index {} is out of range. File contains {} requests",
                    request_index,
                    http_file.requests.len()
                )));
            }
        } else {
            http_file.requests.iter().collect()
        };

        info!(
            "Found {} request(s) in .http file",
            requests_to_execute.len()
        );

        // Execute each request in the file
        for (index, request) in requests_to_execute.iter().enumerate() {
            if let Some(ref name) = request.name {
                info!("Executing request: {}", name);
            } else {
                info!("Executing request #{}", index + 1);
            }

            let start_time = std::time::Instant::now();

            let mut req_builder = crate::request::Request::builder()
                .method(&request.method)
                .url(&request.url)
                .user_agent(&self.config.client.user_agent)
                .timeout(std::time::Duration::from_secs(self.config.client.timeout));

            for (name, value) in &request.headers {
                debug!("Adding header: '{}' = '{}'", name, value);
                if name.trim().is_empty() {
                    debug!("Skipping empty header name");
                    continue;
                }
                req_builder = req_builder.header(name.trim(), value.trim());
            }

            if let Some(ref body) = request.body {
                req_builder = req_builder.body(Some(bytes::Bytes::from(body.clone())));
            }

            let internal_request = req_builder.build()?;

            if let Some(ref cache) = self.cache {
                if let Some(cached_response) = cache.get_response(&internal_request).await? {
                    info!("Serving response from cache");
                    self.display_response(cached_response, cli, start_time)
                        .await?;
                    continue;
                }
            }

            let response = match tokio::time::timeout(
                std::time::Duration::from_secs(self.config.client.timeout),
                self.send_request(internal_request.clone()),
            )
            .await
            {
                Ok(result) => result?,
                Err(_) => return Err(HttpCliError::Timeout),
            };

            if let Some(ref cache) = self.cache {
                cache.store_response(&internal_request, &response).await?;
            }

            self.display_response(response, cli, start_time).await?;

            if http_file.requests.len() > 1 && index < http_file.requests.len() - 1 {
                println!("\n{}\n", "=".repeat(80));
            }
        }

        Ok(())
    }

    async fn execute_benchmark(
        &self,
        _url: &str,
        _requests: u32,
        _concurrency: u32,
        _duration: Option<u64>,
        _cli: &Cli,
    ) -> Result<()> {
        todo!("Benchmarking not yet implemented")
    }

    async fn handle_config_command(&self, show: bool, init: bool) -> Result<()> {
        if init {
            let config_path = Config::init_default_config()?;
            println!(
                "Default configuration created at: {}",
                config_path.display()
            );
        }

        if show {
            println!("{}", serde_yaml::to_string(&self.config)?);
        }

        Ok(())
    }
}
