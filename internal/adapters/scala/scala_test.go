package scala

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Lockfile parser tests
// ---------------------------------------------------------------------------

func TestLoadBuildSbt(t *testing.T) {
	dir := t.TempDir()

	content := `name := "my-app"
scalaVersion := "2.13.12"

libraryDependencies ++= Seq(
  "org.http4s" %% "http4s-client" % "0.23.25",
  "org.http4s" %% "http4s-server" % "0.23.25",
  "io.circe" %% "circe-core" % "0.14.6",
  "io.circe" %% "circe-parser" % "0.14.6",
  "org.postgresql" % "postgresql" % "42.6.0",
  "dev.zio" %% "zio" % "2.0.21",
  "com.typesafe.akka" %% "akka-actor" % "2.8.5",
)
`
	if err := os.WriteFile(filepath.Join(dir, "build.sbt"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	byName := make(map[string]ScalaPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	cases := []struct {
		name    string
		version string
	}{
		{"org.http4s:http4s-client", "0.23.25"},
		{"io.circe:circe-core", "0.14.6"},
		{"org.postgresql:postgresql", "42.6.0"},
		{"dev.zio:zio", "2.0.21"},
		{"com.typesafe.akka:akka-actor", "2.8.5"},
	}
	for _, tc := range cases {
		p, ok := byName[tc.name]
		if !ok {
			t.Errorf("expected %q in packages", tc.name)
			continue
		}
		if p.Version != tc.version {
			t.Errorf("%s version: got %q, want %q", tc.name, p.Version, tc.version)
		}
		if !p.Direct {
			t.Errorf("%s should be direct", tc.name)
		}
	}
}

func TestLoadBuildSbtEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "build.sbt"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	pkgs, err := loadBuildSbt(filepath.Join(dir, "build.sbt"))
	if err != nil {
		t.Fatalf("loadBuildSbt unexpected error: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages for empty build.sbt, got %d", len(pkgs))
	}
}

func TestLoadEmptyDir(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir)
	if err == nil {
		t.Error("expected error for directory with no Scala build files")
	}
}

func TestLoadBuildProperties(t *testing.T) {
	dir := t.TempDir()

	sbtContent := `libraryDependencies += "org.http4s" %% "http4s-client" % "0.23.25"
`
	if err := os.WriteFile(filepath.Join(dir, "build.sbt"), []byte(sbtContent), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(dir, "project"), 0o750); err != nil {
		t.Fatal(err)
	}
	bpContent := "sbt.version=1.9.8\n"
	if err := os.WriteFile(filepath.Join(dir, "project", "build.properties"), []byte(bpContent), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	byName := make(map[string]ScalaPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["sbt:sbt"]; !ok {
		t.Error("expected sbt:sbt meta-package from build.properties")
	}
	if byName["sbt:sbt"].Version != "1.9.8" {
		t.Errorf("sbt version: got %q, want %q", byName["sbt:sbt"].Version, "1.9.8")
	}
}

// ---------------------------------------------------------------------------
// Capability detection tests
// ---------------------------------------------------------------------------

func TestDetectCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `import scala.sys.process._

object Main {
  def main(args: Array[String]): Unit = {
    val result = "ls -la" !
    val pb = new ProcessBuilder("ls")
    val env = System.getenv("HOME")
    val digest = MessageDigest.getInstance("SHA-256")
  }
}
`
	if err := os.WriteFile(filepath.Join(dir, "Main.scala"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)

	wantCaps := []string{"exec", "env", "crypto"}
	for _, want := range wantCaps {
		if !caps.Has(want) {
			t.Errorf("expected capability %q to be detected", want)
		}
	}
}

func TestDetectNoCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `object Utils {
  def add(a: Int, b: Int): Int = a + b

  def greet(name: String): String = s"Hello, $name"

  case class Point(x: Double, y: Double)
}
`
	if err := os.WriteFile(filepath.Join(dir, "Utils.scala"), []byte(src), 0o600); err != nil {
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
	if a.Name() != "scala" {
		t.Errorf("Name(): got %q, want %q", a.Name(), "scala")
	}
}

func TestAdapterLoad(t *testing.T) {
	dir := t.TempDir()

	content := `libraryDependencies ++= Seq(
  "org.http4s" %% "http4s-client" % "0.23.25",
  "dev.zio" %% "zio" % "2.0.21",
)
`
	if err := os.WriteFile(filepath.Join(dir, "build.sbt"), []byte(content), 0o600); err != nil {
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
	if _, ok := g.Packages["org.http4s:http4s-client"]; !ok {
		t.Error("expected org.http4s:http4s-client package in graph")
	}
	if _, ok := g.Packages["dev.zio:zio"]; !ok {
		t.Error("expected dev.zio:zio package in graph")
	}
}

// ---------------------------------------------------------------------------
// Fuzz test
// ---------------------------------------------------------------------------

func FuzzParseBuildSbt(f *testing.F) {
	f.Add([]byte(`libraryDependencies += "org.http4s" %% "http4s-client" % "0.23.25"`))
	f.Add([]byte(`libraryDependencies ++= Seq("dev.zio" %% "zio" % "2.0.21")`))
	f.Add([]byte(""))
	f.Add([]byte("// comment only"))
	f.Add([]byte(`name := "myapp"`))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() { recover() }() //nolint:errcheck

		path := filepath.Join(t.TempDir(), "build.sbt")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return
		}
		loadBuildSbt(path) //nolint:errcheck
	})
}
