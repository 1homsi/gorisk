package java

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Lockfile parser tests
// ---------------------------------------------------------------------------

func TestLoadPomXML(t *testing.T) {
	dir := t.TempDir()
	content := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>myapp</artifactId>
  <version>1.0</version>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>32.0.0-jre</version>
    </dependency>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.14.0</version>
    </dependency>
  </dependencies>
</project>
`
	if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := loadPomXML(dir)
	if err != nil {
		t.Fatalf("loadPomXML: %v", err)
	}

	byName := make(map[string]JavaPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["com.google.guava/guava"]; !ok {
		t.Error("expected 'com.google.guava/guava' in packages")
	}
	if byName["com.google.guava/guava"].Version != "32.0.0-jre" {
		t.Errorf("guava version: got %q, want %q", byName["com.google.guava/guava"].Version, "32.0.0-jre")
	}
	if _, ok := byName["org.apache.commons/commons-lang3"]; !ok {
		t.Error("expected 'org.apache.commons/commons-lang3' in packages")
	}
}

func TestLoadGradleLock(t *testing.T) {
	dir := t.TempDir()
	content := `# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
# This file is expected to be part of source control.
com.google.guava:guava:32.0.0-jre=compileClasspath,runtimeClasspath
org.slf4j:slf4j-api:2.0.9=compileClasspath,runtimeClasspath
empty=
`
	if err := os.WriteFile(filepath.Join(dir, "gradle.lockfile"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := loadGradleLock(dir)
	if err != nil {
		t.Fatalf("loadGradleLock: %v", err)
	}

	byName := make(map[string]JavaPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["com.google.guava/guava"]; !ok {
		t.Error("expected 'com.google.guava/guava' in packages")
	}
	if byName["com.google.guava/guava"].Version != "32.0.0-jre" {
		t.Errorf("guava version: got %q, want %q", byName["com.google.guava/guava"].Version, "32.0.0-jre")
	}
	if _, ok := byName["org.slf4j/slf4j-api"]; !ok {
		t.Error("expected 'org.slf4j/slf4j-api' in packages")
	}
	// "empty=" line should not produce a package.
	if _, ok := byName[""]; ok {
		t.Error("empty line should not produce a package")
	}
}

func TestLoadGradleBuild(t *testing.T) {
	dir := t.TempDir()
	content := `plugins {
    id 'java'
}

dependencies {
    implementation 'com.google.guava:guava:32.0.0-jre'
    testImplementation "junit:junit:4.13.2"
}
`
	if err := os.WriteFile(filepath.Join(dir, "build.gradle"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := loadGradleBuild(dir)
	if err != nil {
		t.Fatalf("loadGradleBuild: %v", err)
	}

	byName := make(map[string]JavaPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["com.google.guava/guava"]; !ok {
		t.Error("expected 'com.google.guava/guava' in packages")
	}
	if _, ok := byName["junit/junit"]; !ok {
		t.Error("expected 'junit/junit' in packages")
	}
}

// ---------------------------------------------------------------------------
// Capability detection tests
// ---------------------------------------------------------------------------

func TestDetectCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `import java.lang.ProcessBuilder;
import java.net.URL;
import java.security.MessageDigest;
import java.lang.reflect.Method;

public class Main {
    public static void main(String[] args) throws Exception {
        new ProcessBuilder("ls").start();
        String key = System.getenv("SECRET_KEY");
        MessageDigest.getInstance("SHA-256");
    }
}
`
	if err := os.WriteFile(filepath.Join(dir, "Main.java"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)

	wantCaps := []string{"exec", "network", "env", "crypto", "reflect"}
	for _, want := range wantCaps {
		if !caps.Has(want) {
			t.Errorf("expected capability %q to be detected", want)
		}
	}
}

func TestDetectNoCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `public class Calculator {
    public int add(int a, int b) {
        return a + b;
    }

    public String greet(String name) {
        return "Hello, " + name;
    }
}
`
	if err := os.WriteFile(filepath.Join(dir, "Calculator.java"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)
	if !caps.IsEmpty() {
		t.Errorf("expected no capabilities for benign code, got: %v", caps.List())
	}
}

// ---------------------------------------------------------------------------
// Adapter integration test
// ---------------------------------------------------------------------------

func TestAdapterLoad(t *testing.T) {
	dir := t.TempDir()
	pom := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>myapp</artifactId>
  <version>1.0</version>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>32.0.0-jre</version>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>2.0.9</version>
    </dependency>
  </dependencies>
</project>
`
	if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(pom), 0o600); err != nil {
		t.Fatal(err)
	}

	a := &Adapter{}
	if a.Name() != "java" {
		t.Errorf("Name(): got %q, want %q", a.Name(), "java")
	}

	g, err := a.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if g == nil {
		t.Fatal("Load returned nil graph")
	}

	// Should have root module + at least the two deps.
	if len(g.Modules) < 2 {
		t.Errorf("expected at least 2 modules, got %d", len(g.Modules))
	}

	if _, ok := g.Packages["com.google.guava/guava"]; !ok {
		t.Error("expected 'com.google.guava/guava' package in graph")
	}
	if _, ok := g.Packages["org.slf4j/slf4j-api"]; !ok {
		t.Error("expected 'org.slf4j/slf4j-api' package in graph")
	}
}

// ---------------------------------------------------------------------------
// Fuzz test
// ---------------------------------------------------------------------------

func FuzzParsePomXML(f *testing.F) {
	f.Add([]byte(`<project><dependencies><dependency><groupId>com.example</groupId><artifactId>lib</artifactId><version>1.0</version></dependency></dependencies></project>`))
	f.Add([]byte(``))
	f.Add([]byte(`<!-- comment only -->`))
	f.Add([]byte(`<project></project>`))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() { recover() }() //nolint:errcheck

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "pom.xml"), data, 0o600); err != nil {
			return
		}
		loadPomXML(dir) //nolint:errcheck
	})
}
