# AGENTS.md

Guidance for Codex when working in this repository.

## Commands

```bash
go build -v ./...
go test -v -race ./...
go tool golangci-lint run
go fmt ./...
go mod tidy
```

Run the targeted package tests while iterating, then run the race tests and linter before finishing meaningful changes.

## Architecture Notes

- `ServerMux` is the central `http.Handler` for HTTP proxying and HTTPS interception.
- HTTPS interception handles `CONNECT` by hijacking the connection, replying `200 Connection established`, then serving client-side TLS with a certificate generated from the configured CA.
- `HTTPInterceptor` implementations run in registration order. `ProcessRequest` may return `skipRemaining=true` to stop later request interceptors; response interceptors run in order for upstream responses.
- Use `ProxyError` for proxy-domain failures so callers and tests can classify errors with `errors.Is` and `errors.As`.

## Tests

- Use `github.com/stretchr/testify`; prefer `require` for setup and fatal checks, `assert` for non-fatal checks.
- Use `t.Parallel()` for independent tests.
- Prefer table-driven tests when cases differ only by inputs and expected results.
- Existing helpers: `setupTestProxy(t testing.TB)` and `setupCertPool(mp *ServerMux)`.
