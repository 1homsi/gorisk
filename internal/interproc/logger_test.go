package interproc

import (
	"bytes"
	"strings"
	"testing"
)

func TestLogger(t *testing.T) {
	// Save original state
	origVerbose := Verbose
	origLogger := Logger
	defer func() {
		Verbose = origVerbose
		Logger = origLogger
	}()

	// Redirect output to buffer
	var buf bytes.Buffer
	SetOutput(&buf)
	SetVerbose(true)

	// Test debug logging
	Debugf("test debug: %s", "message")
	output := buf.String()
	if !strings.Contains(output, "[DEBUG] test debug: message") {
		t.Errorf("Expected debug message, got: %s", output)
	}

	// Test verbose off
	buf.Reset()
	SetVerbose(false)
	Debugf("should not appear")
	if buf.Len() > 0 {
		t.Errorf("Expected no output when verbose=false, got: %s", buf.String())
	}

	// Test error always prints
	buf.Reset()
	Errorf("error message")
	output = buf.String()
	if !strings.Contains(output, "[ERROR] error message") {
		t.Errorf("Expected error message even with verbose=false, got: %s", output)
	}
}

func TestLogLevels(t *testing.T) {
	// Save original state
	origVerbose := Verbose
	origLogger := Logger
	defer func() {
		Verbose = origVerbose
		Logger = origLogger
	}()

	var buf bytes.Buffer
	SetOutput(&buf)
	SetVerbose(true)

	// Test all log levels
	Debugf("debug")
	Infof("info")
	Warnf("warn")
	Errorf("error")

	output := buf.String()
	levels := []string{"[DEBUG]", "[INFO]", "[WARN]", "[ERROR]"}
	for _, level := range levels {
		if !strings.Contains(output, level) {
			t.Errorf("Expected %s in output, got: %s", level, output)
		}
	}
}
