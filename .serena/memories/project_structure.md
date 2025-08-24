# Project Structure

## Root Files
- `mitmproxxy.go` - Core proxy server implementation with ServerMux
- `interceptor.go` - Interceptor interface and implementations
- `errors.go` - Custom error types and error handling
- `go.mod` / `go.sum` - Go module dependencies
- `CLAUDE.md` - Claude Code guidance and documentation
- `README.md` - Project documentation
- `LICENSE` - Project license

## Test Files
- `mitmproxxy_test.go` - Tests for core proxy functionality
- `interceptor_test.go` - Tests for interceptors
- `errors_test.go` - Tests for error handling
- `test_helpers_test.go` - Shared test utilities and helpers

## Directories
- `example/` - Example implementations
  - `mitm/main.go` - Simple MITM proxy example
  - `proxy/main.go` - Full-featured proxy with interceptors
- `testdata/` - Test certificates and data
  - Contains CA certificates for testing MITM functionality
- `.github/` - GitHub Actions workflows and configuration
- `.serena/` - Serena MCP configuration
- `.claude/` - Claude Code configuration

## Core Components Architecture

### 1. ServerMux (`mitmproxxy.go`)
- Main HTTP/HTTPS proxy handler
- Manages TLS handshakes
- Dynamic certificate generation
- Interceptor chain execution
- Connection hijacking for CONNECT requests

### 2. Interceptor System (`interceptor.go`)
- `HTTPInterceptor` interface for request/response modification
- Chain of Responsibility pattern
- Built-in interceptors:
  - `LoggingInterceptor` - Request/response logging
  - `ContentModifierInterceptor` - Header and body modification
  - `FilteringInterceptor` - Request blocking based on rules
  - `RequestIDInterceptor` - Unique ID tracking

### 3. Error System (`errors.go`)
- `ProxyError` struct for structured errors
- Error type categorization
- Proper error wrapping and context

## Data Flow
1. Client → Proxy (CONNECT for HTTPS, direct for HTTP)
2. Proxy → TLS Handshake (for HTTPS)
3. Request → Interceptor Chain → Target Server
4. Response ← Interceptor Chain ← Target Server
5. Response → Client