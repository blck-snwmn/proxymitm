# Code Style and Conventions

## Naming Conventions
- **Interfaces**: PascalCase ending with "-er" suffix (e.g., `HTTPInterceptor`, `HTTPClient`, `RequestCreator`, `TLSHandshaker`)
- **Structs**: PascalCase (e.g., `ServerMux`, `LoggingInterceptor`, `ProxyError`)
- **Methods**: PascalCase for exported, camelCase for unexported
- **Constants**: PascalCase with descriptive prefixes (e.g., `DefaultReadTimeout`, `LogLevelDebug`, `ErrHijack`)
- **Variables**: camelCase for local variables
- **Test functions**: Test_ prefix followed by function name (e.g., `Test_createX509Certificate`)

## Code Organization
- Main types and interfaces defined at the top of files
- Interface implementations use pointer receivers consistently
- Error handling uses custom `ProxyError` type for domain-specific errors
- Proper error wrapping with `errors.Is` and `errors.As` support

## Testing Patterns
- Table-driven tests for multiple scenarios
- Use `github.com/stretchr/testify` for assertions
- `require` for critical checks that should stop test execution
- `assert` for checks that allow test continuation
- Always use `t.Parallel()` for independent tests
- Helper functions in `test_helpers_test.go`
- Variable shadowing in range loops for parallel tests (e.g., `tt := tt`)

## Error Handling
- Structured errors using `ProxyError` type with:
  - Error type categorization (ErrHijack, ErrTLSHandshake, etc.)
  - Operation context
  - Descriptive messages
  - Original error wrapping
- Consistent error checking and early returns
- Proper resource cleanup with defer statements

## Logging
- Structured logging with levels (Debug, Info, Warn, Error)
- Logger interface for flexibility
- Descriptive log messages with context
- Format: `[LEVEL] message with %v placeholders`

## Comments and Documentation
- Exported types and methods have godoc comments
- Comments start with the name of the element being described
- No unnecessary inline comments unless explicitly needed
- Clear, concise documentation focusing on purpose and behavior