package node

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectFunctions(t *testing.T) {
	dir := t.TempDir()

	// Create test file with various function styles
	testCode := `
const { exec } = require('child_process');
const fs = require('fs');
const crypto = require('crypto');

// Regular function declaration
function runCommand(cmd) {
	exec(cmd, (err, stdout) => {
		console.log(stdout);
	});
}

// Arrow function with exec
const executeShell = async () => {
	const result = exec('ls -la');
	return result;
};

// Function with file operations
function readConfig() {
	const data = fs.readFileSync('/etc/config');
	return JSON.parse(data);
}

// Function with crypto
const hashPassword = (password) => {
	return crypto.createHash('sha256').update(password).digest('hex');
};

// Class method
class FileManager {
	writeFile(path, content) {
		fs.writeFileSync(path, content);
	}
}

// Function that calls other functions
function processData() {
	const config = readConfig();
	const hash = hashPassword(config.password);
	runCommand('echo done');
	return hash;
}
`

	testFile := filepath.Join(dir, "test.js")
	if err := os.WriteFile(testFile, []byte(testCode), 0600); err != nil {
		t.Fatal(err)
	}

	funcs, edges, err := DetectFunctions(dir, []string{"test.js"})
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Found %d functions", len(funcs))
	for key, fc := range funcs {
		t.Logf("  %s: %s (score: %d)", key, fc.DirectCaps.String(), fc.DirectCaps.Score)
	}

	// Verify we found functions
	if len(funcs) == 0 {
		t.Error("Expected to find functions, got 0")
	}

	// Check for specific functions
	foundRunCommand := false
	foundReadConfig := false
	foundHashPassword := false

	for _, fc := range funcs {
		if fc.Symbol.Name == "runCommand" {
			foundRunCommand = true
			if !fc.DirectCaps.Has("exec") {
				t.Error("runCommand should have exec capability")
			}
		}
		if fc.Symbol.Name == "readConfig" {
			foundReadConfig = true
			if !fc.DirectCaps.Has("fs:read") {
				t.Error("readConfig should have fs:read capability")
			}
		}
		if fc.Symbol.Name == "hashPassword" {
			foundHashPassword = true
			if !fc.DirectCaps.Has("crypto") {
				t.Error("hashPassword should have crypto capability")
			}
		}
	}

	if !foundRunCommand {
		t.Error("Expected to find runCommand function")
	}
	if !foundReadConfig {
		t.Error("Expected to find readConfig function")
	}
	if !foundHashPassword {
		t.Error("Expected to find hashPassword function")
	}

	// Check call edges
	t.Logf("Found %d call edges", len(edges))
	if len(edges) == 0 {
		t.Error("Expected to find call edges")
	}

	// Verify processData calls other functions
	foundProcessDataEdge := false
	for _, edge := range edges {
		if edge.Caller.Name == "processData" {
			foundProcessDataEdge = true
			t.Logf("processData calls: %s", edge.Callee.Name)
		}
	}

	if !foundProcessDataEdge {
		t.Error("Expected to find processData calling other functions")
	}
}

func TestFindFunctions(t *testing.T) {
	source := `
function foo() {
	return 42;
}

const bar = () => {
	return 'hello';
};

async function baz() {
	await fetch('https://api.example.com');
}

class MyClass {
	methodOne() {
		return 1;
	}
}
`

	functions := findFunctions(source, "test.js")

	if len(functions) == 0 {
		t.Fatal("Expected to find functions")
	}

	names := make(map[string]bool)
	for _, fn := range functions {
		names[fn.Name] = true
		t.Logf("Found function: %s (lines %d-%d)", fn.Name, fn.StartLine, fn.EndLine)
	}

	expected := []string{"foo", "bar", "baz", "methodOne"}
	for _, name := range expected {
		if !names[name] {
			t.Errorf("Expected to find function: %s", name)
		}
	}
}

func TestFindFunctionCalls(t *testing.T) {
	body := `
	const result = processData();
	helper.doSomething();
	await fetchData();
	arr.map(transform);
	`

	calls := findFunctionCalls(body)

	expected := map[string]bool{
		"processData": true,
		"doSomething": true,
		"fetchData":   true,
		"transform":   true,
	}

	for _, call := range calls {
		if !expected[call] {
			t.Logf("Unexpected call: %s", call)
		}
		delete(expected, call)
	}

	for missing := range expected {
		t.Errorf("Expected to find call: %s", missing)
	}
}
