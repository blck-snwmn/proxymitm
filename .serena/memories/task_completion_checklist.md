# Task Completion Checklist

When completing any coding task in this project, ALWAYS run these commands in order:

## 1. Code Quality Checks (MANDATORY)
```bash
# Format the code
go fmt ./...

# Run linter - MUST PASS
go tool golangci-lint run

# Run go vet
go vet ./...
```

## 2. Testing (MANDATORY)
```bash
# Run all tests with race detection - MUST PASS
go test -v -race ./...
```

## 3. Build Verification
```bash
# Verify the project builds successfully
go build -v ./...
```

## 4. Dependency Check (if dependencies were modified)
```bash
# Clean up go.mod if dependencies were added/removed
go mod tidy
```

## Important Notes
- **NEVER** commit code that doesn't pass `golangci-lint`
- **NEVER** commit code that doesn't pass tests with race detection
- **ALWAYS** ensure proper error handling with `ProxyError` type
- **ALWAYS** follow the established interceptor pattern when adding new interceptors
- **ALWAYS** add tests for new functionality using table-driven test pattern
- **ALWAYS** use `t.Parallel()` for independent tests

## Common Issues to Check
- Resource leaks: Ensure all connections, files, and bodies are properly closed
- Race conditions: Must pass `go test -race`
- Error wrapping: Use `NewProxyError` for domain errors
- Logging: Add appropriate debug/info/error logs
- Test coverage: New code should have corresponding tests