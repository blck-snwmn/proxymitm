# Project Overview

## Project Purpose
proxymitm is a Go-based HTTP/HTTPS proxy server with Man-in-the-Middle (MITM) capabilities. It allows intercepting, inspecting, and modifying HTTP/HTTPS traffic between clients and servers.

## Technology Stack
- **Language**: Go 1.24.1
- **Testing Framework**: stretchr/testify v1.10.0
- **Linting**: golangci-lint (installed as go tool)
- **Build System**: Go modules

## Main Features
- HTTP/HTTPS proxy server with MITM support
- Dynamic certificate generation for TLS interception
- Interceptor chain pattern for request/response modification
- Built-in interceptors:
  - LoggingInterceptor: Logs requests and responses
  - ContentModifierInterceptor: Modifies headers and body content
  - FilteringInterceptor: Blocks requests based on host, path, or user agent
  - RequestIDInterceptor: Adds unique request IDs for tracking
- Structured error handling with ProxyError type
- Configurable logging levels (Debug, Info, Warn, Error)

## Project Type
This is a library project that provides MITM proxy functionality that can be integrated into other applications. The example directory contains sample implementations showing how to use the library.