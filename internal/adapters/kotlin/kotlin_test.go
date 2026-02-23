package kotlin

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Lockfile parser tests
// ---------------------------------------------------------------------------

func TestLoadLibsVersionsToml(t *testing.T) {
	dir := t.TempDir()

	content := `[versions]
ktor = "2.3.7"
kotlin = "1.9.22"
jackson-version = "2.16.1"

[libraries]
ktor-client-core = { module = "io.ktor:ktor-client-core", version.ref = "ktor" }
ktor-server-netty = { module = "io.ktor:ktor-server-netty", version.ref = "ktor" }
jackson = { module = "com.fasterxml.jackson.core:jackson-databind", version = "2.16.1" }

[bundles]
ktor = ["ktor-client-core", "ktor-server-netty"]
`
	if err := os.MkdirAll(filepath.Join(dir, "gradle"), 0o750); err != nil {
		t.Fatal(err)
	}
	tomlPath := filepath.Join(dir, "gradle", "libs.versions.toml")
	if err := os.WriteFile(tomlPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	byName := make(map[string]KotlinPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["io.ktor:ktor-client-core"]; !ok {
		t.Error("expected io.ktor:ktor-client-core in packages")
	}
	if byName["io.ktor:ktor-client-core"].Version != "2.3.7" {
		t.Errorf("ktor-client-core version: got %q, want %q",
			byName["io.ktor:ktor-client-core"].Version, "2.3.7")
	}
	if _, ok := byName["com.fasterxml.jackson.core:jackson-databind"]; !ok {
		t.Error("expected jackson-databind in packages")
	}
	if byName["com.fasterxml.jackson.core:jackson-databind"].Version != "2.16.1" {
		t.Errorf("jackson version: got %q, want %q",
			byName["com.fasterxml.jackson.core:jackson-databind"].Version, "2.16.1")
	}
	if !byName["io.ktor:ktor-client-core"].Direct {
		t.Error("io.ktor:ktor-client-core should be direct")
	}
}

func TestLoadBuildGradleKts(t *testing.T) {
	dir := t.TempDir()

	content := `plugins {
    kotlin("jvm") version "1.9.22"
}

dependencies {
    implementation("io.ktor:ktor-client-core:2.3.7")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.1")
    api("com.fasterxml.jackson.core:jackson-databind:2.16.1")
    compileOnly("org.bouncycastle:bcprov-jdk18on:1.77")
}
`
	if err := os.WriteFile(filepath.Join(dir, "build.gradle.kts"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	byName := make(map[string]KotlinPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["io.ktor:ktor-client-core"]; !ok {
		t.Error("expected io.ktor:ktor-client-core")
	}
	if byName["io.ktor:ktor-client-core"].Version != "2.3.7" {
		t.Errorf("ktor version: got %q, want %q", byName["io.ktor:ktor-client-core"].Version, "2.3.7")
	}
	if _, ok := byName["com.squareup.okhttp3:okhttp"]; !ok {
		t.Error("expected com.squareup.okhttp3:okhttp")
	}
	if _, ok := byName["com.fasterxml.jackson.core:jackson-databind"]; !ok {
		t.Error("expected jackson-databind")
	}
	if _, ok := byName["org.bouncycastle:bcprov-jdk18on"]; !ok {
		t.Error("expected bcprov-jdk18on")
	}
	for _, p := range pkgs {
		if !p.Direct {
			t.Errorf("package %s should be direct", p.Name)
		}
	}
}

func TestLoadBuildGradle(t *testing.T) {
	dir := t.TempDir()

	content := `apply plugin: 'java'

dependencies {
    implementation 'io.ktor:ktor-client-core:2.3.7'
    implementation "com.squareup.okhttp3:okhttp:4.12.0"
    testImplementation 'org.junit.jupiter:junit-jupiter:5.10.1'
    api "com.fasterxml.jackson.core:jackson-databind:2.16.1"
    runtimeOnly 'ch.qos.logback:logback-classic:1.4.14'
}
`
	if err := os.WriteFile(filepath.Join(dir, "build.gradle"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	byName := make(map[string]KotlinPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["io.ktor:ktor-client-core"]; !ok {
		t.Error("expected io.ktor:ktor-client-core")
	}
	if _, ok := byName["com.squareup.okhttp3:okhttp"]; !ok {
		t.Error("expected com.squareup.okhttp3:okhttp")
	}
	if _, ok := byName["ch.qos.logback:logback-classic"]; !ok {
		t.Error("expected logback-classic")
	}
}

func TestLoadEmptyDir(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir)
	if err == nil {
		t.Error("expected error for directory with no Kotlin build files")
	}
}

// ---------------------------------------------------------------------------
// Capability detection tests
// ---------------------------------------------------------------------------

func TestDetectCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `import io.ktor.client.HttpClient
import io.ktor.client.request.get

fun main() {
    val pb = ProcessBuilder("ls", "-la")
    val env = System.getenv("SECRET_KEY")
    val digest = MessageDigest.getInstance("SHA-256")
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.kt"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)

	wantCaps := []string{"network", "exec", "env", "crypto"}
	for _, want := range wantCaps {
		if !caps.Has(want) {
			t.Errorf("expected capability %q to be detected", want)
		}
	}
}

func TestDetectNoCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `fun add(a: Int, b: Int): Int = a + b

fun greet(name: String): String = "Hello, $name"

data class Point(val x: Double, val y: Double)
`
	if err := os.WriteFile(filepath.Join(dir, "utils.kt"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)
	if !caps.IsEmpty() {
		t.Errorf("expected no capabilities for benign code, got: %v", caps.List())
	}
}

// ---------------------------------------------------------------------------
// Adapter tests
// ---------------------------------------------------------------------------

func TestAdapterName(t *testing.T) {
	a := Adapter{}
	if a.Name() != "kotlin" {
		t.Errorf("Name(): got %q, want %q", a.Name(), "kotlin")
	}
}

func TestAdapterLoad(t *testing.T) {
	dir := t.TempDir()

	content := `dependencies {
    implementation("io.ktor:ktor-client-core:2.3.7")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
}
`
	if err := os.WriteFile(filepath.Join(dir, "build.gradle.kts"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	a := Adapter{}
	g, err := a.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if g == nil {
		t.Fatal("Load returned nil graph")
	}
	if len(g.Modules) < 2 {
		t.Errorf("expected at least 2 modules (root + deps), got %d", len(g.Modules))
	}
	if _, ok := g.Packages["io.ktor:ktor-client-core"]; !ok {
		t.Error("expected io.ktor:ktor-client-core package in graph")
	}
	if _, ok := g.Packages["com.squareup.okhttp3:okhttp"]; !ok {
		t.Error("expected com.squareup.okhttp3:okhttp package in graph")
	}
}

// ---------------------------------------------------------------------------
// Fuzz test
// ---------------------------------------------------------------------------

func FuzzParseLibsVersionsToml(f *testing.F) {
	f.Add([]byte(`[versions]
ktor = "2.3.7"
[libraries]
ktor-client-core = { module = "io.ktor:ktor-client-core", version.ref = "ktor" }
`))
	f.Add([]byte(""))
	f.Add([]byte("[versions]\n"))
	f.Add([]byte("[libraries]\nalias = { module = \"group:artifact\" }"))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() { recover() }() //nolint:errcheck

		path := filepath.Join(t.TempDir(), "libs.versions.toml")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return
		}
		loadLibsVersionsToml(path) //nolint:errcheck
	})
}
