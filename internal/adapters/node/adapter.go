package node

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/interproc"
	"github.com/1homsi/gorisk/internal/ir"
)

// Adapter implements the Analyzer interface for Node.js projects.
type Adapter struct{}

func (a *Adapter) Name() string { return "node" }

// Load parses the project's lockfile, detects capabilities for each npm
// package, and returns a *graph.DependencyGraph using the same structure as
// the Go loader.
func (a *Adapter) Load(dir string) (*graph.DependencyGraph, error) {
	interproc.Infof("[node] Starting Node.js project analysis")
	interproc.Debugf("[node] Project directory: %s", dir)

	pkgs, err := Load(dir)
	if err != nil {
		interproc.Errorf("[node] Failed to load lockfile: %v", err)
		return nil, err
	}

	interproc.Infof("[node] Loaded %d packages from lockfile", len(pkgs))
	g := graph.NewDependencyGraph()

	// Build root module from package.json name (or directory basename)
	rootName := filepath.Base(dir)
	if name := readPackageJSONName(dir); name != "" {
		rootName = name
	}

	rootMod := &graph.Module{
		Path: rootName,
		Dir:  dir,
		Main: true,
	}
	g.Modules[rootName] = rootMod
	g.Main = rootMod

	// Root package — represents the project's own source files
	interproc.Infof("[node] Analyzing root package: %s", rootName)
	interproc.Debugf("[node] Root directory: %s", dir)
	rootPkg := &graph.Package{
		ImportPath:   rootName,
		Name:         rootName,
		Module:       rootMod,
		Dir:          dir,
		Capabilities: Detect(dir),
	}
	g.Packages[rootName] = rootPkg
	rootMod.Packages = append(rootMod.Packages, rootPkg)
	if !rootPkg.Capabilities.IsEmpty() {
		interproc.Infof("[node] ✓ ROOT (%s): %s (score: %d, risk: %s)",
			rootName, rootPkg.Capabilities.String(), rootPkg.Capabilities.Score, rootPkg.Capabilities.RiskLevel())
	} else {
		interproc.Debugf("[node] ✓ ROOT (%s): (no capabilities detected)", rootName)
	}

	// Track which packages are direct dependencies of root
	var rootEdges []string

	// Deduplicate packages by name (keep first seen)
	seen := make(map[string]bool)
	analyzed := 0

	interproc.Debugf("[node] Analyzing %d npm packages", len(pkgs))
	for _, npmPkg := range pkgs {
		if seen[npmPkg.Name] {
			continue
		}
		seen[npmPkg.Name] = true

		mod := &graph.Module{
			Path:    npmPkg.Name,
			Version: npmPkg.Version,
			Dir:     npmPkg.Dir,
		}
		g.Modules[npmPkg.Name] = mod

		pkg := &graph.Package{
			ImportPath: npmPkg.Name,
			Name:       npmPkg.Name,
			Module:     mod,
			Dir:        npmPkg.Dir,
		}

		// Detect capabilities from the package's source files (if present)
		if npmPkg.Dir != "" {
			if _, statErr := os.Stat(npmPkg.Dir); statErr == nil {
				pkg.Capabilities = Detect(npmPkg.Dir)
				analyzed++

				// Log individual package analysis
				if !pkg.Capabilities.IsEmpty() {
					interproc.Debugf("[node] ✓ %s: %s (score: %d)",
						npmPkg.Name, pkg.Capabilities.String(), pkg.Capabilities.Score)
				} else {
					interproc.Debugf("[node] ✓ %s: (no capabilities)", npmPkg.Name)
				}

				// Progress updates
				if analyzed%100 == 0 {
					interproc.Infof("[node] Progress: %d/%d packages analyzed", analyzed, len(pkgs))
				}
			} else {
				interproc.Debugf("[node] ⊘ %s: (source not available)", npmPkg.Name)
			}
		} else {
			interproc.Debugf("[node] ⊘ %s: (no directory)", npmPkg.Name)
		}

		g.Packages[npmPkg.Name] = pkg
		mod.Packages = append(mod.Packages, pkg)
		g.Edges[npmPkg.Name] = npmPkg.Dependencies

		if npmPkg.Direct {
			rootEdges = append(rootEdges, npmPkg.Name)
		}
	}

	g.Edges[rootName] = rootEdges

	interproc.Infof("[node] Analyzed %d packages", analyzed)

	// Check for workspaces
	workspaces := workspaceDirs(dir)
	if len(workspaces) > 0 {
		interproc.Debugf("[node] Found %d workspace packages", len(workspaces))
	}

	for _, wsDir := range workspaces {
		wsName := filepath.Base(wsDir)
		if name := readPackageJSONName(wsDir); name != "" {
			wsName = name
		}
		if _, exists := g.Modules[wsName]; exists {
			continue
		}
		wsMod := &graph.Module{
			Path: wsName,
			Dir:  wsDir,
			Main: true,
		}
		g.Modules[wsName] = wsMod

		wsPkg := &graph.Package{
			ImportPath:   wsName,
			Name:         wsName,
			Module:       wsMod,
			Dir:          wsDir,
			Capabilities: Detect(wsDir),
		}
		interproc.Debugf("[node] ✓ WORKSPACE (%s): %s (score: %d)",
			wsName, wsPkg.Capabilities.String(), wsPkg.Capabilities.Score)
		g.Packages[wsName] = wsPkg
		wsMod.Packages = append(wsMod.Packages, wsPkg)

		wsDirect := readDirectDeps(wsDir)
		var wsEdges []string
		for dep := range wsDirect {
			if _, exists := g.Packages[dep]; exists {
				wsEdges = append(wsEdges, dep)
			}
		}
		g.Edges[wsName] = wsEdges
	}

	// Run interprocedural analysis and propagate enhanced capabilities back to packages.
	if err := runInterproceduralAnalysis(g); err != nil {
		interproc.Warnf("[node] Interprocedural analysis failed: %v", err)
		// Continue without interprocedural results
	}

	interproc.Infof("[node] Analysis complete: %d total packages, %d modules", len(g.Packages), len(g.Modules))
	return g, nil
}

// runInterproceduralAnalysis builds a function-level call graph, runs the interprocedural
// engine, and merges the enhanced (transitive) capabilities back into each package.
func runInterproceduralAnalysis(g *graph.DependencyGraph) error {
	// Build IRGraph from function-level analysis
	irGraph := buildNodeFunctionIRGraph(g)
	if len(irGraph.Functions) == 0 {
		return nil // Nothing to analyze
	}

	// Run interprocedural analysis with k=1 (context-sensitive, function-level)
	opts := interproc.DefaultOptions()
	opts.ContextSensitivity = 1

	csGraph, _, err := interproc.RunAnalysis(irGraph, opts)
	if err != nil {
		return err
	}

	// Roll up context-sensitive summaries to package level — same pattern as Go adapter.
	for nodeKey, node := range csGraph.Nodes {
		summary := csGraph.Summaries[nodeKey]
		pkg := g.Packages[node.Function.Package]
		if pkg == nil {
			continue
		}
		pkg.Capabilities.MergeWithEvidence(summary.Transitive)
	}

	interproc.Infof("[node] Interprocedural capabilities merged into %d packages", len(g.Packages))
	return nil
}

// buildNodeFunctionIRGraph converts packages into a function-level IRGraph.
// Uses funcdetector.go to parse JavaScript/TypeScript and build a function-level call graph.
func buildNodeFunctionIRGraph(g *graph.DependencyGraph) ir.IRGraph {
	irGraph := ir.IRGraph{
		Functions: make(map[string]ir.FunctionCaps),
		Calls:     []ir.CallEdge{},
	}

	// Analyze each package's source files for functions
	for _, pkg := range g.Packages {
		if pkg.Dir == "" {
			continue
		}

		// Find JavaScript/TypeScript files
		jsFiles, err := filepath.Glob(filepath.Join(pkg.Dir, "*.js"))
		if err != nil {
			continue
		}
		tsFiles, err := filepath.Glob(filepath.Join(pkg.Dir, "*.ts"))
		if err == nil {
			jsFiles = append(jsFiles, tsFiles...)
		}

		if len(jsFiles) == 0 {
			continue
		}

		// Extract just filenames for DetectFunctions
		var fileNames []string
		for _, fpath := range jsFiles {
			fileNames = append(fileNames, filepath.Base(fpath))
		}

		// Detect functions in this package
		funcs, edges, err := DetectFunctions(pkg.Dir, fileNames)
		if err != nil {
			interproc.Warnf("[node] Failed to detect functions in %s: %v", pkg.ImportPath, err)
			continue
		}

		// Add functions to IRGraph
		for key, fc := range funcs {
			irGraph.Functions[key] = fc
		}

		// Add call edges
		irGraph.Calls = append(irGraph.Calls, edges...)
	}

	interproc.Infof("[node] Built function-level IR: %d functions, %d call edges",
		len(irGraph.Functions), len(irGraph.Calls))

	return irGraph
}

func readPackageJSONName(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return ""
	}
	var pkgJSON struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(data, &pkgJSON) != nil {
		return ""
	}
	return pkgJSON.Name
}

var rePnpmWorkspace = regexp.MustCompile(`^\s*-\s+['"]?([^'"#\s]+)['"]?`)

func workspaceDirs(root string) []string {
	var patterns []string

	data, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err == nil {
		var pkgJSON struct {
			Workspaces json.RawMessage `json:"workspaces"`
		}
		if json.Unmarshal(data, &pkgJSON) == nil && len(pkgJSON.Workspaces) > 0 {
			var list []string
			if json.Unmarshal(pkgJSON.Workspaces, &list) == nil {
				patterns = append(patterns, list...)
			} else {
				var obj struct {
					Packages []string `json:"packages"`
				}
				if json.Unmarshal(pkgJSON.Workspaces, &obj) == nil {
					patterns = append(patterns, obj.Packages...)
				}
			}
		}
	}

	if yamlData, err := os.ReadFile(filepath.Join(root, "pnpm-workspace.yaml")); err == nil {
		for _, line := range strings.Split(string(yamlData), "\n") {
			if m := rePnpmWorkspace.FindStringSubmatch(line); m != nil {
				patterns = append(patterns, m[1])
			}
		}
	}

	if len(patterns) == 0 {
		return nil
	}

	seen := make(map[string]bool)
	var dirs []string
	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(root, pattern))
		if err != nil {
			continue
		}
		for _, match := range matches {
			if seen[match] {
				continue
			}
			info, err := os.Stat(match)
			if err != nil || !info.IsDir() {
				continue
			}
			if _, err := os.Stat(filepath.Join(match, "package.json")); err != nil {
				continue
			}
			seen[match] = true
			dirs = append(dirs, match)
		}
	}
	return dirs
}
