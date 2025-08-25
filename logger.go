package proxymitm

import (
	"log"
)

// LogLevel represents the logging level
type LogLevel int

const (
	// LogLevelDebug represents the debug level log
	LogLevelDebug LogLevel = iota
	// LogLevelInfo represents the information level log
	LogLevelInfo
	// LogLevelWarn represents the warning level log
	LogLevelWarn
	// LogLevelError represents the error level log
	LogLevelError
)

// Logger defines the logging interface
type Logger interface {
	Debug(format string, v ...interface{})
	Info(format string, v ...interface{})
	Warn(format string, v ...interface{})
	Error(format string, v ...interface{})
}

// DefaultLogger is the default logger implementation
type DefaultLogger struct {
	level LogLevel
}

// NewDefaultLogger creates a new default logger
func NewDefaultLogger(level LogLevel) *DefaultLogger {
	return &DefaultLogger{
		level: level,
	}
}

// Debug outputs logs at debug level
func (l *DefaultLogger) Debug(format string, v ...interface{}) {
	if l.level <= LogLevelDebug {
		log.Printf("[DEBUG] "+format, v...)
	}
}

// Info outputs logs at information level
func (l *DefaultLogger) Info(format string, v ...interface{}) {
	if l.level <= LogLevelInfo {
		log.Printf("[INFO] "+format, v...)
	}
}

// Warn outputs logs at warning level
func (l *DefaultLogger) Warn(format string, v ...interface{}) {
	if l.level <= LogLevelWarn {
		log.Printf("[WARN] "+format, v...)
	}
}

// Error outputs logs at error level
func (l *DefaultLogger) Error(format string, v ...interface{}) {
	if l.level <= LogLevelError {
		log.Printf("[ERROR] "+format, v...)
	}
}
