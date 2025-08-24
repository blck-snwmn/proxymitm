# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Development Commands

### Build Commands
```bash
# Build the project
go build

# Build all packages
go build -v ./...

# Build examples
go build ./example/mitm/
go build ./example/proxy/
```

### Test Commands
```bash
# Run all tests with race detection (used in CI)
go test -v -race ./...

# Run tests with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run tests for current package
go test .

# Run tests for a specific package
go test ./example/...
```

### Code Quality Commands
```bash
# Run golangci-lint (installed as go tool via go.mod)
# Note: This uses the tool directive in go.mod (line 194)
go tool golangci-lint run

# Format code
go fmt ./...

# Run go vet
go vet ./...
```

### Dependency Management
```bash
# Clean up go.mod
go mod tidy

# Download dependencies
go mod download
```

### Running the Server
```bash
# Run simple MITM proxy example
go run ./example/mitm/main.go

# Run full-featured proxy example
go run ./example/proxy/main.go

# Test with curl
curl https://target -x localhost:18080 --cacert ./testdata/ca.crt
```

## Architecture Overview

### Core Components

1. **ServerMux** (`mitmproxxy.go`)
   - Main HTTP/HTTPS proxy server handler
   - Manages TLS handshakes and dynamic certificate generation
   - Executes interceptor chains for request/response processing

2. **HTTPInterceptor Interface** (`interceptor.go`)
   - Core abstraction for request/response modification
   - Supports chaining multiple interceptors
   - ProcessRequest can skip remaining interceptors with `skipRemaining` flag

3. **Error System** (`errors.go`)
   - Structured error handling with `ProxyError` type
   - Categorized error types (ErrHijack, ErrTLSHandshake, etc.)

### HTTPS Interception Flow

1. Client sends CONNECT request to proxy
2. Proxy responds with "200 Connection established"
3. Proxy performs TLS handshake with client using dynamically generated certificate
4. Proxy decrypts client request, processes through interceptors
5. Proxy establishes connection with target server
6. Response flows back through interceptors to client

### Interceptor Pattern

Interceptors process requests and responses in sequence:
- Request processing can halt chain with `skipRemaining = true`
- Response processing always runs through all interceptors
- Built-in interceptors: LoggingInterceptor, ContentModifierInterceptor, FilteringInterceptor, RequestIDInterceptor

### Testing Guidelines

- Use `github.com/stretchr/testify` for assertions
- Use `require` for critical checks that should stop test execution
- Use `assert` for checks that allow test continuation
- Always use `t.Parallel()` for independent tests
- Use table-driven tests for multiple similar scenarios
- Helper functions available in `test_helpers_test.go`:
  - `setupTestProxy(t testing.TB)` - creates test MITM proxy
  - `setupCertPool(mp *ServerMux)` - sets up TLS certificates

### Code Quality Requirements

- All code must pass `go tool golangci-lint run`
- Tests must pass with race detection (`go test -race`)
- Use structured `ProxyError` for domain-specific errors
- Implement proper error wrapping with `errors.Is` and `errors.As`