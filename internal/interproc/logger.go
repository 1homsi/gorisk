package interproc

import (
	"io"
	"log"
	"os"
)

// Global logger configuration
var (
	// Logger is the global logger for interprocedural analysis
	Logger *log.Logger

	// Verbose controls whether debug messages are printed
	Verbose bool
)

func init() {
	// Initialize logger to stderr with timestamp
	Logger = log.New(os.Stderr, "", log.Ltime|log.Lmicroseconds)

	// Enable verbose logging if environment variable is set (for backward compatibility)
	// Can be overridden by SetVerbose() when using --verbose flag
	Verbose = os.Getenv("GORISK_VERBOSE") == "1"
}

// SetVerbose enables or disables verbose logging at runtime
func SetVerbose(enabled bool) {
	Verbose = enabled
}

// SetOutput redirects logger output (useful for testing)
func SetOutput(w io.Writer) {
	Logger.SetOutput(w)
}

// Debugf prints a debug message if verbose mode is enabled
func Debugf(format string, args ...interface{}) {
	if Verbose {
		Logger.Printf("[DEBUG] "+format, args...)
	}
}

// Infof prints an info message if verbose mode is enabled
func Infof(format string, args ...interface{}) {
	if Verbose {
		Logger.Printf("[INFO] "+format, args...)
	}
}

// Warnf prints a warning message if verbose mode is enabled
func Warnf(format string, args ...interface{}) {
	if Verbose {
		Logger.Printf("[WARN] "+format, args...)
	}
}

// Errorf always prints an error message regardless of verbose mode
func Errorf(format string, args ...interface{}) {
	Logger.Printf("[ERROR] "+format, args...)
}
