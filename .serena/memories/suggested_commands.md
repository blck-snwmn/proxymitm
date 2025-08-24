# Suggested Commands for Development

## Build Commands
```bash
# Build the main project
go build

# Build all packages including sub-packages
go build -v ./...

# Build example programs
go build ./example/mitm/
go build ./example/proxy/
```

## Testing Commands
```bash
# Run all tests with race detection (REQUIRED before commits)
go test -v -race ./...

# Run tests with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run specific test file
go test ./mitmproxxy_test.go
```

## Code Quality Commands
```bash
# Run linter (MUST pass before commits)
go tool golangci-lint run

# Format code
go fmt ./...

# Run go vet for basic checks
go vet ./...
```

## Dependency Management
```bash
# Clean up and verify dependencies
go mod tidy

# Download all dependencies
go mod download
```

## Running Examples
```bash
# Run simple MITM proxy example
go run ./example/mitm/main.go

# Run full-featured proxy example with interceptors
go run ./example/proxy/main.go

# Test proxy with curl
curl https://target -x localhost:18080 --cacert ./testdata/ca.crt
```

## System Commands (Darwin/macOS)
```bash
# List files
ls -la

# Find files
find . -name "*.go"

# Search in files (use ripgrep)
rg "pattern" .

# Git operations
git status
git diff
git log --oneline -n 10
```