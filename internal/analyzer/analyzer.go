package analyzer

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	clojureadapter "github.com/1homsi/gorisk/internal/adapters/clojure"
	cppadapter "github.com/1homsi/gorisk/internal/adapters/cpp"
	dartadapter "github.com/1homsi/gorisk/internal/adapters/dart"
	dotnetadapter "github.com/1homsi/gorisk/internal/adapters/dotnet"
	elixiradapter "github.com/1homsi/gorisk/internal/adapters/elixir"
	erlangadapter "github.com/1homsi/gorisk/internal/adapters/erlang"
	goadapter "github.com/1homsi/gorisk/internal/adapters/go"
	haskelladapter "github.com/1homsi/gorisk/internal/adapters/haskell"
	javaadapter "github.com/1homsi/gorisk/internal/adapters/java"
	juliaadapter "github.com/1homsi/gorisk/internal/adapters/julia"
	kotlinadapter "github.com/1homsi/gorisk/internal/adapters/kotlin"
	luaadapter "github.com/1homsi/gorisk/internal/adapters/lua"
	nodeadapter "github.com/1homsi/gorisk/internal/adapters/node"
	ocamladapter "github.com/1homsi/gorisk/internal/adapters/ocaml"
	perladapter "github.com/1homsi/gorisk/internal/adapters/perl"
	phpadapter "github.com/1homsi/gorisk/internal/adapters/php"
	pythonadapter "github.com/1homsi/gorisk/internal/adapters/python"
	radapter "github.com/1homsi/gorisk/internal/adapters/r"
	rubyadapter "github.com/1homsi/gorisk/internal/adapters/ruby"
	rustadapter "github.com/1homsi/gorisk/internal/adapters/rust"
	scalaadapter "github.com/1homsi/gorisk/internal/adapters/scala"
	swiftadapter "github.com/1homsi/gorisk/internal/adapters/swift"
	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/prdiff"
	"github.com/1homsi/gorisk/internal/reachability"
	"github.com/1homsi/gorisk/internal/upgrade"
)

// LangFeatures holds the feature implementations registered for a language.
type LangFeatures struct {
	Upgrade      upgrade.Upgrader
	CapDiff      upgrade.CapDiffer
	PRDiff       prdiff.Differ
	Reachability reachability.Analyzer
}

var registry = map[string]LangFeatures{
	"go": {
		Upgrade:      upgrade.GoUpgrader{},
		CapDiff:      upgrade.GoCapDiffer{},
		PRDiff:       prdiff.GoDiffer{},
		Reachability: reachability.GoAnalyzer{},
	},
	"node": {
		Upgrade:      upgrade.NodeUpgrader{},
		CapDiff:      upgrade.NodeCapDiffer{},
		PRDiff:       prdiff.NodeDiffer{},
		Reachability: reachability.NodeAnalyzer{},
	},
	"php": {
		Upgrade:      upgrade.PHPUpgrader{},
		CapDiff:      upgrade.PHPCapDiffer{},
		PRDiff:       prdiff.PHPDiffer{},
		Reachability: reachability.PHPAnalyzer{},
	},
	"python": {
		Upgrade:      upgrade.PythonUpgrader{},
		CapDiff:      upgrade.PythonCapDiffer{},
		PRDiff:       prdiff.PythonDiffer{},
		Reachability: reachability.PythonAnalyzer{},
	},
	"java": {
		Upgrade:      upgrade.JavaUpgrader{},
		CapDiff:      upgrade.JavaCapDiffer{},
		PRDiff:       prdiff.JavaDiffer{},
		Reachability: reachability.JavaAnalyzer{},
	},
	"rust": {
		Upgrade:      upgrade.RustUpgrader{},
		CapDiff:      upgrade.RustCapDiffer{},
		PRDiff:       prdiff.RustDiffer{},
		Reachability: reachability.RustAnalyzer{},
	},
	"ruby": {
		Upgrade:      upgrade.RubyUpgrader{},
		CapDiff:      upgrade.RubyCapDiffer{},
		PRDiff:       prdiff.RubyDiffer{},
		Reachability: reachability.RubyAnalyzer{},
	},
	"elixir": {
		Upgrade:      upgrade.ElixirUpgrader{},
		CapDiff:      upgrade.ElixirCapDiffer{},
		PRDiff:       prdiff.ElixirDiffer{},
		Reachability: reachability.ElixirAnalyzer{},
	},
	"swift": {
		Upgrade:      upgrade.SwiftUpgrader{},
		CapDiff:      upgrade.SwiftCapDiffer{},
		PRDiff:       prdiff.SwiftDiffer{},
		Reachability: reachability.SwiftAnalyzer{},
	},
	"dart": {
		Upgrade:      upgrade.DartUpgrader{},
		CapDiff:      upgrade.DartCapDiffer{},
		PRDiff:       prdiff.DartDiffer{},
		Reachability: reachability.DartAnalyzer{},
	},
	"dotnet": {
		Upgrade:      upgrade.DotnetUpgrader{},
		CapDiff:      upgrade.DotnetCapDiffer{},
		PRDiff:       prdiff.DotnetDiffer{},
		Reachability: reachability.DotnetAnalyzer{},
	},
	"kotlin": {
		Upgrade:      upgrade.KotlinUpgrader{},
		CapDiff:      upgrade.KotlinCapDiffer{},
		PRDiff:       prdiff.KotlinDiffer{},
		Reachability: reachability.KotlinAnalyzer{},
	},
	"scala": {
		Upgrade:      upgrade.ScalaUpgrader{},
		CapDiff:      upgrade.ScalaCapDiffer{},
		PRDiff:       prdiff.ScalaDiffer{},
		Reachability: reachability.ScalaAnalyzer{},
	},
	"cpp": {
		Upgrade:      upgrade.CppUpgrader{},
		CapDiff:      upgrade.CppCapDiffer{},
		PRDiff:       prdiff.CppDiffer{},
		Reachability: reachability.CppAnalyzer{},
	},
	"haskell": {
		Upgrade:      upgrade.HaskellUpgrader{},
		CapDiff:      upgrade.HaskellCapDiffer{},
		PRDiff:       prdiff.HaskellDiffer{},
		Reachability: reachability.HaskellAnalyzer{},
	},
	"clojure": {
		Upgrade:      upgrade.ClojureUpgrader{},
		CapDiff:      upgrade.ClojureCapDiffer{},
		PRDiff:       prdiff.ClojureDiffer{},
		Reachability: reachability.ClojureAnalyzer{},
	},
	"erlang": {
		Upgrade:      upgrade.ErlangUpgrader{},
		CapDiff:      upgrade.ErlangCapDiffer{},
		PRDiff:       prdiff.ErlangDiffer{},
		Reachability: reachability.ErlangAnalyzer{},
	},
	"ocaml": {
		Upgrade:      upgrade.OCamlUpgrader{},
		CapDiff:      upgrade.OCamlCapDiffer{},
		PRDiff:       prdiff.OCamlDiffer{},
		Reachability: reachability.OCamlAnalyzer{},
	},
	"julia": {
		Upgrade:      upgrade.JuliaUpgrader{},
		CapDiff:      upgrade.JuliaCapDiffer{},
		PRDiff:       prdiff.JuliaDiffer{},
		Reachability: reachability.JuliaAnalyzer{},
	},
	"r": {
		Upgrade:      upgrade.RUpgrader{},
		CapDiff:      upgrade.RCapDiffer{},
		PRDiff:       prdiff.RDiffer{},
		Reachability: reachability.RAnalyzer{},
	},
	"perl": {
		Upgrade:      upgrade.PerlUpgrader{},
		CapDiff:      upgrade.PerlCapDiffer{},
		PRDiff:       prdiff.PerlDiffer{},
		Reachability: reachability.PerlAnalyzer{},
	},
	"lua": {
		Upgrade:      upgrade.LuaUpgrader{},
		CapDiff:      upgrade.LuaCapDiffer{},
		PRDiff:       prdiff.LuaDiffer{},
		Reachability: reachability.LuaAnalyzer{},
	},
}

// FeaturesFor returns the feature implementations for the given language.
// lang may be "auto", "go", "node", "php", "python", "java", "rust", or "ruby".
func FeaturesFor(lang, dir string) (LangFeatures, error) {
	if lang == "auto" || lang == "" {
		lang = detect(dir)
		if lang == "multi" {
			lang = "go" // multi-repo: default to go for non-graph features
		}
	}
	f, ok := registry[lang]
	if !ok {
		return LangFeatures{}, fmt.Errorf("unknown language %q; choose auto|go|node|php|python|java|rust|ruby|elixir|dart|swift|dotnet|kotlin|scala|cpp|haskell|clojure|erlang|ocaml|julia|r|perl|lua", lang)
	}
	return f, nil
}

// Analyzer loads a dependency graph for a project directory.
type Analyzer interface {
	Name() string
	Load(dir string) (*graph.DependencyGraph, error)
}

// ForLang returns an Analyzer for the given language specifier.
// lang may be "auto", "go", "node", "php", "python", "java", "rust", "ruby",
// "elixir", "dart", "swift", "dotnet", "kotlin", "scala", "cpp", "haskell",
// "clojure", "erlang", "ocaml", "julia", "r", "perl", or "lua".
// "auto" detects from lockfile / manifest presence.
func ForLang(lang, dir string) (Analyzer, error) {
	if lang == "auto" {
		lang = detect(dir)
	}
	switch lang {
	case "go":
		return &goadapter.Adapter{}, nil
	case "node":
		return &nodeadapter.Adapter{}, nil
	case "php":
		return &phpadapter.Adapter{}, nil
	case "python":
		return &pythonadapter.Adapter{}, nil
	case "java":
		return &javaadapter.Adapter{}, nil
	case "rust":
		return &rustadapter.Adapter{}, nil
	case "ruby":
		return &rubyadapter.Adapter{}, nil
	case "dart":
		return dartadapter.Adapter{}, nil
	case "elixir":
		return elixiradapter.Adapter{}, nil
	case "swift":
		return &swiftadapter.Adapter{}, nil
	case "dotnet":
		return &dotnetadapter.Adapter{}, nil
	case "kotlin":
		return &kotlinadapter.Adapter{}, nil
	case "scala":
		return &scalaadapter.Adapter{}, nil
	case "cpp":
		return &cppadapter.Adapter{}, nil
	case "haskell":
		return &haskelladapter.Adapter{}, nil
	case "clojure":
		return &clojureadapter.Adapter{}, nil
	case "erlang":
		return &erlangadapter.Adapter{}, nil
	case "ocaml":
		return &ocamladapter.Adapter{}, nil
	case "julia":
		return &juliaadapter.Adapter{}, nil
	case "r":
		return &radapter.Adapter{}, nil
	case "perl":
		return &perladapter.Adapter{}, nil
	case "lua":
		return &luaadapter.Adapter{}, nil
	case "multi":
		return &multiAnalyzer{}, nil
	default:
		return nil, fmt.Errorf("unknown language %q; choose auto|go|node|php|python|java|rust|ruby|elixir|dart|swift|dotnet|kotlin|scala|cpp|haskell|clojure|erlang|ocaml|julia|r|perl|lua", lang)
	}
}

func detect(dir string) string {
	hasGoMod := fileExists(filepath.Join(dir, "go.mod"))
	hasPkgJSON := fileExists(filepath.Join(dir, "package.json"))
	hasComposerJSON := fileExists(filepath.Join(dir, "composer.json"))
	hasComposerLock := fileExists(filepath.Join(dir, "composer.lock"))
	hasPyprojectTOML := fileExists(filepath.Join(dir, "pyproject.toml"))
	hasPoetryLock := fileExists(filepath.Join(dir, "poetry.lock"))
	hasPipfileLock := fileExists(filepath.Join(dir, "Pipfile.lock"))
	hasRequirementsTxt := fileExists(filepath.Join(dir, "requirements.txt"))
	hasPomXML := fileExists(filepath.Join(dir, "pom.xml"))
	hasGradleLock := fileExists(filepath.Join(dir, "gradle.lockfile"))
	hasBuildGradleKts := fileExists(filepath.Join(dir, "build.gradle.kts"))
	hasBuildGradle := fileExists(filepath.Join(dir, "build.gradle")) || hasBuildGradleKts
	hasCargoToml := fileExists(filepath.Join(dir, "Cargo.toml"))
	hasGemfileLock := fileExists(filepath.Join(dir, "Gemfile.lock"))
	hasGemfile := fileExists(filepath.Join(dir, "Gemfile"))
	hasPubspecLock := fileExists(filepath.Join(dir, "pubspec.lock"))
	hasPubspecYAML := fileExists(filepath.Join(dir, "pubspec.yaml"))
	hasMixLock := fileExists(filepath.Join(dir, "mix.lock"))
	hasMixExs := fileExists(filepath.Join(dir, "mix.exs"))
	hasPackageResolved := fileExists(filepath.Join(dir, "Package.resolved"))
	hasPackageSwift := fileExists(filepath.Join(dir, "Package.swift"))
	// .NET
	hasPackagesLockJSON := fileExists(filepath.Join(dir, "packages.lock.json"))
	hasCsprojGlob := func() bool {
		matches, _ := filepath.Glob(filepath.Join(dir, "*.csproj"))
		return len(matches) > 0
	}()
	// Kotlin — libs.versions.toml or build.gradle.kts distinguish from plain Java
	hasLibsVersionsToml := fileExists(filepath.Join(dir, "libs.versions.toml")) ||
		fileExists(filepath.Join(dir, "gradle", "libs.versions.toml"))
	// Scala
	hasBuildSbt := fileExists(filepath.Join(dir, "build.sbt"))
	// C/C++
	hasVcpkgJSON := fileExists(filepath.Join(dir, "vcpkg.json"))
	hasConanfile := fileExists(filepath.Join(dir, "conanfile.py")) || fileExists(filepath.Join(dir, "conanfile.txt"))
	// Haskell
	hasCabalFreeze := fileExists(filepath.Join(dir, "cabal.project.freeze"))
	hasStackLock := fileExists(filepath.Join(dir, "stack.yaml.lock"))
	hasCabalGlob := func() bool {
		matches, _ := filepath.Glob(filepath.Join(dir, "*.cabal"))
		return len(matches) > 0
	}()
	// Clojure
	hasDepsEdn := fileExists(filepath.Join(dir, "deps.edn"))
	hasProjectClj := fileExists(filepath.Join(dir, "project.clj"))
	// Erlang
	hasRebarLock := fileExists(filepath.Join(dir, "rebar.lock"))
	hasRebarConfig := fileExists(filepath.Join(dir, "rebar.config"))
	// OCaml
	hasOpamLocked := func() bool {
		matches, _ := filepath.Glob(filepath.Join(dir, "*.opam.locked"))
		return len(matches) > 0 || fileExists(filepath.Join(dir, "opam.locked"))
	}()
	hasOpamFile := func() bool {
		matches, _ := filepath.Glob(filepath.Join(dir, "*.opam"))
		return len(matches) > 0
	}()
	// Julia
	hasManifestToml := fileExists(filepath.Join(dir, "Manifest.toml"))
	// R
	hasRenvLock := fileExists(filepath.Join(dir, "renv.lock"))
	hasDescription := fileExists(filepath.Join(dir, "DESCRIPTION"))
	// Perl
	hasCpanfileSnapshot := fileExists(filepath.Join(dir, "cpanfile.snapshot"))
	hasCpanfile := fileExists(filepath.Join(dir, "cpanfile"))
	// Lua
	hasLuarocksLock := fileExists(filepath.Join(dir, "luarocks.lock"))
	hasRockspec := func() bool {
		matches, _ := filepath.Glob(filepath.Join(dir, "*.rockspec"))
		return len(matches) > 0
	}()

	isPython := hasPyprojectTOML || hasPoetryLock || hasPipfileLock || hasRequirementsTxt
	isKotlin := hasLibsVersionsToml || hasBuildGradleKts
	isJava := !isKotlin && (hasPomXML || hasGradleLock || hasBuildGradle)
	isRust := hasCargoToml
	isRuby := hasGemfileLock || hasGemfile
	isDart := hasPubspecLock || hasPubspecYAML
	isElixir := hasMixLock || hasMixExs
	isSwift := hasPackageResolved || hasPackageSwift
	isDotnet := hasPackagesLockJSON || hasCsprojGlob
	isScala := hasBuildSbt
	isCpp := hasVcpkgJSON || hasConanfile
	isHaskell := hasCabalFreeze || hasStackLock || hasCabalGlob
	isClojure := hasDepsEdn || hasProjectClj
	isErlang := hasRebarLock || hasRebarConfig
	isOCaml := hasOpamLocked || hasOpamFile
	isJulia := hasManifestToml
	isR := hasRenvLock || hasDescription
	isPerl := hasCpanfileSnapshot || hasCpanfile
	isLua := hasLuarocksLock || hasRockspec

	switch {
	case hasGoMod && hasPkgJSON:
		return "multi"
	case hasGoMod:
		return "go"
	case hasPkgJSON:
		return "node"
	case hasComposerJSON || hasComposerLock:
		return "php"
	case isPython:
		return "python"
	case isKotlin:
		return "kotlin"
	case isJava:
		return "java"
	case isRust:
		return "rust"
	case isRuby:
		return "ruby"
	case isDart:
		return "dart"
	case isElixir:
		return "elixir"
	case isSwift:
		return "swift"
	case isDotnet:
		return "dotnet"
	case isScala:
		return "scala"
	case isCpp:
		return "cpp"
	case isHaskell:
		return "haskell"
	case isClojure:
		return "clojure"
	case isErlang:
		return "erlang"
	case isOCaml:
		return "ocaml"
	case isJulia:
		return "julia"
	case isR:
		return "r"
	case isPerl:
		return "perl"
	case isLua:
		return "lua"
	default:
		return "go"
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ResolveLang resolves "auto" to a concrete language key using project detection.
// It may return "multi".
func ResolveLang(lang, dir string) string {
	if lang == "auto" || lang == "" {
		return detect(dir)
	}
	return lang
}

// multiAnalyzer runs both Go and Node analyzers and merges the results.
type multiAnalyzer struct{}

func (m *multiAnalyzer) Name() string { return "multi" }

func (m *multiAnalyzer) Load(dir string) (*graph.DependencyGraph, error) {
	goA := &goadapter.Adapter{}
	nodeA := &nodeadapter.Adapter{}

	goG, goErr := goA.Load(dir)
	nodeG, nodeErr := nodeA.Load(dir)

	if goErr != nil && nodeErr != nil {
		return nil, fmt.Errorf("go: %w; node: %w", goErr, nodeErr)
	}
	if goErr != nil {
		return nodeG, nil
	}
	if nodeErr != nil {
		return goG, nil
	}
	return mergeGraphs(goG, nodeG), nil
}

func mergeGraphs(a, b *graph.DependencyGraph) *graph.DependencyGraph {
	merged := graph.NewDependencyGraph()
	if a.Main != nil {
		merged.Main = a.Main
	} else {
		merged.Main = b.Main
	}
	for k, v := range a.Modules {
		merged.Modules[k] = v
	}
	for k, v := range b.Modules {
		merged.Modules[k] = v
	}
	for k, v := range a.Packages {
		merged.Packages[k] = v
	}
	for k, v := range b.Packages {
		merged.Packages[k] = v
	}
	for k, v := range a.Edges {
		merged.Edges[k] = v
	}
	for k, v := range b.Edges {
		merged.Edges[k] = v
	}
	return merged
}

// LoadWorkspace detects a monorepo/workspace root and scans all members as a
// unified project. It supports three workspace formats:
//
//   - go.work             → Go workspace (contains multiple Go modules via "use" directives)
//   - package.json with   → npm workspaces (supports glob patterns like "packages/*")
//     "workspaces" field
//   - pnpm-workspace.yaml → pnpm workspace (packages: list)
//
// For each workspace member directory, the appropriate language adapter's
// Load method is called and the resulting graphs are merged.
func LoadWorkspace(root string) (*graph.DependencyGraph, error) {
	// Try go.work first
	if fileExists(filepath.Join(root, "go.work")) {
		return loadGoWorkspace(root)
	}

	// Try pnpm-workspace.yaml
	if fileExists(filepath.Join(root, "pnpm-workspace.yaml")) {
		return loadPnpmWorkspace(root)
	}

	// Try npm workspaces (package.json with "workspaces" field)
	if fileExists(filepath.Join(root, "package.json")) {
		return loadNpmWorkspace(root)
	}

	return nil, fmt.Errorf("no workspace file found in %s (looked for go.work, pnpm-workspace.yaml, package.json with workspaces)", root)
}

// loadGoWorkspace parses go.work and loads each member module.
func loadGoWorkspace(root string) (*graph.DependencyGraph, error) {
	goWorkPath := filepath.Join(root, "go.work")
	f, err := os.Open(goWorkPath)
	if err != nil {
		return nil, fmt.Errorf("open go.work: %w", err)
	}
	defer f.Close()

	var memberDirs []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Match lines like: use ./path/to/module
		// Also handles the block form: use (\n   ./path\n)
		if strings.HasPrefix(line, "use ") {
			path := strings.TrimSpace(strings.TrimPrefix(line, "use "))
			// Strip parentheses for single-line block form "use ( ./foo )"
			path = strings.Trim(path, "()")
			path = strings.TrimSpace(path)
			if path != "" && path != "(" {
				memberDirs = append(memberDirs, filepath.Join(root, filepath.FromSlash(path)))
			}
		} else if line != "(" && line != ")" && !strings.HasPrefix(line, "//") && !strings.HasPrefix(line, "go ") && !strings.HasPrefix(line, "toolchain ") {
			// Inside a use block, lines are bare paths
			// We handle them if they look like relative paths
			if strings.HasPrefix(line, "./") || strings.HasPrefix(line, "../") {
				memberDirs = append(memberDirs, filepath.Join(root, filepath.FromSlash(line)))
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read go.work: %w", err)
	}

	if len(memberDirs) == 0 {
		return nil, fmt.Errorf("go.work has no 'use' directives")
	}

	goA := &goadapter.Adapter{}
	merged := graph.NewDependencyGraph()
	for _, memberDir := range memberDirs {
		g, err := goA.Load(memberDir)
		if err != nil {
			return nil, fmt.Errorf("load workspace member %s: %w", memberDir, err)
		}
		merged = mergeGraphs(merged, g)
	}
	return merged, nil
}

// loadPnpmWorkspace parses pnpm-workspace.yaml and loads each member.
func loadPnpmWorkspace(root string) (*graph.DependencyGraph, error) {
	data, err := os.ReadFile(filepath.Join(root, "pnpm-workspace.yaml"))
	if err != nil {
		return nil, fmt.Errorf("read pnpm-workspace.yaml: %w", err)
	}

	// Simple YAML parsing: look for lines under "packages:" that start with "  - "
	var patterns []string
	inPackages := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimRight(line, " \t\r")
		if trimmed == "packages:" {
			inPackages = true
			continue
		}
		if inPackages {
			// A new top-level key ends the packages block
			if len(trimmed) > 0 && trimmed[0] != ' ' && trimmed[0] != '\t' && trimmed[0] != '#' && trimmed[0] != '-' {
				inPackages = false
				continue
			}
			// Strip list prefix "  - " or "- "
			item := strings.TrimSpace(trimmed)
			if strings.HasPrefix(item, "- ") {
				item = strings.TrimPrefix(item, "- ")
				item = strings.Trim(item, "\"'")
				patterns = append(patterns, item)
			} else if strings.HasPrefix(item, "-") {
				item = strings.TrimPrefix(item, "-")
				item = strings.TrimSpace(item)
				item = strings.Trim(item, "\"'")
				if item != "" {
					patterns = append(patterns, item)
				}
			}
		}
	}

	memberDirs, err := resolveGlobPatterns(root, patterns)
	if err != nil {
		return nil, fmt.Errorf("resolve pnpm workspace patterns: %w", err)
	}

	return loadNodeMemberDirs(memberDirs)
}

// loadNpmWorkspace parses package.json workspaces field and loads each member.
func loadNpmWorkspace(root string) (*graph.DependencyGraph, error) {
	data, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		return nil, fmt.Errorf("read package.json: %w", err)
	}

	var pkg struct {
		Workspaces []string `json:"workspaces"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("parse package.json: %w", err)
	}
	if len(pkg.Workspaces) == 0 {
		return nil, fmt.Errorf("package.json has no 'workspaces' field")
	}

	memberDirs, err := resolveGlobPatterns(root, pkg.Workspaces)
	if err != nil {
		return nil, fmt.Errorf("resolve npm workspace patterns: %w", err)
	}

	return loadNodeMemberDirs(memberDirs)
}

// resolveGlobPatterns expands glob patterns relative to root into concrete
// directories that contain a package.json file.
func resolveGlobPatterns(root string, patterns []string) ([]string, error) {
	var dirs []string
	seen := make(map[string]bool)
	for _, pattern := range patterns {
		// Strip trailing "/**" or "/*" — filepath.Glob handles one level; we
		// only need the immediate members.
		globPat := pattern
		if strings.HasSuffix(globPat, "/**") {
			globPat = strings.TrimSuffix(globPat, "/**") + "/*"
		}

		absGlob := filepath.Join(root, filepath.FromSlash(globPat))
		matches, err := filepath.Glob(absGlob)
		if err != nil {
			return nil, fmt.Errorf("glob %q: %w", absGlob, err)
		}

		for _, m := range matches {
			info, err := os.Stat(m)
			if err != nil || !info.IsDir() {
				continue
			}
			if !fileExists(filepath.Join(m, "package.json")) {
				continue
			}
			if !seen[m] {
				seen[m] = true
				dirs = append(dirs, m)
			}
		}
	}
	return dirs, nil
}

// loadNodeMemberDirs loads each member directory with the Node adapter and
// merges the resulting graphs.
func loadNodeMemberDirs(memberDirs []string) (*graph.DependencyGraph, error) {
	if len(memberDirs) == 0 {
		return nil, fmt.Errorf("no workspace members found")
	}

	nodeA := &nodeadapter.Adapter{}
	merged := graph.NewDependencyGraph()
	for _, memberDir := range memberDirs {
		g, err := nodeA.Load(memberDir)
		if err != nil {
			return nil, fmt.Errorf("load workspace member %s: %w", memberDir, err)
		}
		merged = mergeGraphs(merged, g)
	}
	return merged, nil
}
