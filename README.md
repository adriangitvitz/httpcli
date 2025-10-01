# httpcli

A high-performance HTTP CLI tool with .http file support and syntax highlighting, built in Rust.

## Features

- **High Performance**: Built with Tokio async runtime and optimized for speed with LTO and mimalloc
- **.http File Support**: Parse and execute requests from .http files with variable substitution
- **Syntax Highlighting**: Beautiful colored output for JSON responses
- **Multiple HTTP Methods**: Support for GET, POST, PUT, DELETE, PATCH, HEAD, and OPTIONS
- **Authentication**: Basic auth, bearer tokens, and custom headers
- **TLS/SSL**: Full TLS support with custom CA certificates and client certificates
- **HTTP/2**: Support for both HTTP/1.1 and HTTP/2
- **Compression**: Automatic handling of gzip and brotli compression
- **Benchmarking**: Built-in performance testing capabilities
- **Request Caching**: Intelligent response caching
- **Variable Substitution**: Support for environment variables and custom variables in .http files

## Installation

### From Source

```bash
git clone https://github.com/adriannajera/httpcli
cd httpcli
cargo build --release
```

The binary will be available at `target/release/httpcli`.

### Prerequisites

- Rust 1.70 or higher
- OpenSSL development libraries (for TLS support)

## Usage

### Basic HTTP Requests

```bash
# Simple GET request
httpcli GET https://api.example.com/users

# POST request with JSON data
httpcli POST https://api.example.com/users -d '{"name": "John Doe", "email": "john@example.com"}'

# Add custom headers
httpcli GET https://api.example.com/protected -H "Authorization: Bearer token123"

# PUT request with data
httpcli PUT https://api.example.com/users/1 -d '{"name": "Jane Doe"}'
```

### Using Subcommands

```bash
# GET request
httpcli get https://httpbin.org/ip

# POST request
httpcli post https://httpbin.org/post -d '{"test": "data"}'

# DELETE request
httpcli delete https://api.example.com/users/1
```

### .http File Support

Create a `.http` file with your requests:

```http
@baseUrl = https://httpbin.org
@token = your_token_here

# @name Get IP
GET {{baseUrl}}/ip

###

# @name Post JSON Data
POST {{baseUrl}}/post
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "name": "Test User",
  "email": "test@example.com",
  "data": {
    "key": "value",
    "number": 42
  }
}

###
```

Execute the file:

```bash
httpcli --file requests.http
```

Or using the subcommand:

```bash
httpcli file requests.http
```

### Authentication

```bash
# Basic authentication
httpcli GET https://api.example.com/protected -a username:password

# Bearer token
httpcli GET https://api.example.com/protected --token your_token_here

# Custom authorization header
httpcli GET https://api.example.com/protected -H "Authorization: Bearer token123"
```

### Output Options

```bash
# Pretty formatted output (default)
httpcli GET https://api.example.com/users --output pretty

# JSON output only
httpcli GET https://api.example.com/users --output json

# Show headers only
httpcli GET https://api.example.com/users --output headers

# Raw body only
httpcli GET https://api.example.com/users --output body

# Verbose output
httpcli GET https://api.example.com/users --output verbose

# Show timing information
httpcli GET https://api.example.com/users --timing

# Show response headers
httpcli GET https://api.example.com/users --headers
```

### Advanced Features

```bash
# Follow redirects
httpcli GET https://example.com/redirect --follow --max-redirects 5

# Set custom timeout
httpcli GET https://api.example.com/slow -t 60

# Custom User-Agent
httpcli GET https://api.example.com/users --user-agent "MyApp/1.0"

# Enable compression
httpcli GET https://api.example.com/large-data --compress

# Use proxy
httpcli GET https://api.example.com/users --proxy http://proxy.example.com:8080

# Save response to file
httpcli GET https://api.example.com/data --save response.json

# Read body from file
httpcli POST https://api.example.com/upload --data-binary file.json

# Disable TLS verification (insecure)
httpcli GET https://self-signed.example.com --insecure
```

### TLS/SSL Options

```bash
# Custom CA certificate
httpcli GET https://api.example.com --cacert /path/to/ca.pem

# Client certificate authentication
httpcli GET https://api.example.com --cert /path/to/client.crt --key /path/to/client.key

# Specify HTTP version
httpcli GET https://api.example.com --http-version 2
```

### Benchmarking

```bash
# Run 1000 requests with 50 concurrent connections
httpcli benchmark -n 1000 -c 50 https://api.example.com/health

# Run benchmark for 30 seconds
httpcli benchmark -d 30 -c 10 https://api.example.com/health
```

### Variables and Environment

```bash
# Use environment variables file
httpcli --env-file .env --file requests.http

# Pass variables via command line
httpcli --file requests.http --var baseUrl=https://api.example.com --var token=abc123

# Environment variables with HTTP_ prefix are automatically loaded
export HTTP_BASE_URL=https://api.example.com
httpcli --file requests.http
```

### Configuration

```bash
# Initialize default configuration
httpcli config --init

# Show current configuration
httpcli config --show

# Use custom configuration file
httpcli --config /path/to/config.toml GET https://api.example.com
```

### Syntax Highlighting

```bash
# Enable/disable syntax highlighting
httpcli GET https://api.example.com/users --highlight true

# Choose color theme
httpcli GET https://api.example.com/users --theme base16-ocean.dark
```

### Logging

```bash
# Enable verbose logging
httpcli -v GET https://api.example.com/users

# Very verbose (multiple -v flags)
httpcli -vvv GET https://api.example.com/users

# Silent mode (only output response body)
httpcli -s GET https://api.example.com/users

# Set log level via environment variable
RUST_LOG=debug httpcli GET https://api.example.com/users
```

## .http File Format

The tool supports the standard .http file format used by popular HTTP clients:

- **Variables**: Define with `@variableName = value`
- **Variable References**: Use with `{{variableName}}`
- **Request Names**: Comment with `# @name RequestName`
- **Request Separator**: Use `###` to separate multiple requests
- **Headers**: One per line after the request line
- **Body**: Add after a blank line following headers

Example:

```http
@host = api.example.com
@apiKey = your-api-key

# @name List Users
GET https://{{host}}/users
Authorization: Bearer {{apiKey}}

###

# @name Create User
POST https://{{host}}/users
Content-Type: application/json
Authorization: Bearer {{apiKey}}

{
  "name": "John Doe",
  "email": "john@example.com"
}

###
```

## Architecture

The project is structured into several modules:

- **cli**: Command-line argument parsing and interface
- **client**: HTTP client implementation with connection pooling
- **http_parser**: Parser for .http files using nom combinators
- **request**: HTTP request building and formatting
- **response**: HTTP response handling and formatting
- **syntax**: Syntax highlighting for JSON and other formats
- **tls**: TLS/SSL certificate handling
- **cache**: Response caching implementation
- **config**: Configuration file management
- **error**: Error types and handling

## Performance Optimizations

- **mimalloc**: Fast memory allocator for improved performance
- **LTO**: Link-time optimization enabled in release builds
- **HTTP/2**: Support for multiplexing and header compression
- **Connection Pooling**: Reuse connections for better performance
- **Async I/O**: Built on Tokio for efficient concurrency
- **Smart Caching**: Cache responses to reduce redundant requests

## License

MIT OR Apache-2.0
