// Package logger provides the logger for the application
package logger

import (
	"os"

	"github.com/sirupsen/logrus"
)

var log *logrus.Logger

// Init initializes the global logger with configuration from environment
func Init() {
	log = logrus.New()

	// Set log level from environment
	level := getLogLevel()
	log.SetLevel(level)

	// Set formatter
	log.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
	})

	// Set output to stdout
	log.SetOutput(os.Stdout)

	// Log the initialization
	log.WithField("level", level.String()).Info("Logger initialized")
}

// getLogLevel reads LOG_LEVEL from environment, defaults to INFO
func getLogLevel() logrus.Level {
	levelStr := os.Getenv("LOG_LEVEL")
	if levelStr == "" {
		levelStr = "info"
	}

	level, err := logrus.ParseLevel(levelStr)
	if err != nil {
		// Default to INFO if invalid level
		return logrus.InfoLevel
	}

	return level
}

// Get returns the global logger instance
func Get() *logrus.Logger {
	if log == nil {
		Init()
	}
	return log
}

// Helper functions for common logging patterns

// Infof logs an info message with formatting
func Infof(format string, args ...interface{}) {
	Get().Infof(format, args...)
}

// Errorf logs an error message with formatting
func Errorf(format string, args ...interface{}) {
	Get().Errorf(format, args...)
}

// Warnf logs a warning message with formatting
func Warnf(format string, args ...interface{}) {
	Get().Warnf(format, args...)
}

// Debugf logs a debug message with formatting
func Debugf(format string, args ...interface{}) {
	Get().Debugf(format, args...)
}

// WithField creates a logger with a field
func WithField(key string, value interface{}) *logrus.Entry {
	return Get().WithField(key, value)
}

// WithFields creates a logger with multiple fields
func WithFields(fields logrus.Fields) *logrus.Entry {
	return Get().WithFields(fields)
}

// WithError creates a logger with an error field
func WithError(err error) *logrus.Entry {
	return Get().WithError(err)
}
