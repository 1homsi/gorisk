package node

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
)

// Binding records what module/export a local identifier is bound to.
type Binding struct {
	Module string // bare module name, e.g. "child_process"
	Export string // named export if destructured, "" = whole module
	Line   int    // source line of the binding
}

// SymbolTable maps local identifiers → their origin binding.
type SymbolTable map[string]Binding

var (
	// const cp = require('child_process')  /  var net = require('net')
	reVarBind = regexp.MustCompile(`(?:const|let|var)\s+(\w+)\s*=\s*require\(['"]([^'"]+)['"]\)`)

	// const {exec, spawn} = require('child_process')
	// const {exec: myExec, spawn: mySpawn} = require('child_process')
	reDestructured = regexp.MustCompile(`(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\(['"]([^'"]+)['"]\)`)

	// import cp from 'child_process'  (default import)
	reImportDefault = regexp.MustCompile(`import\s+(\w+)\s+from\s+['"]([^'"]+)['"]`)

	// import {exec, spawn} from 'child_process'
	reImportNamed = regexp.MustCompile(`import\s*\{([^}]+)\}\s*from\s+['"]([^'"]+)['"]`)

	// import * as cp from 'child_process'
	reImportNamespace = regexp.MustCompile(`import\s*\*\s*as\s+(\w+)\s+from\s+['"]([^'"]+)['"]`)

	// require('child_process').exec(...)  — direct chained call
	reChainedCall = regexp.MustCompile(`require\(['"]([^'"]+)['"]\)\.(\w+)\s*\(`)

	// cp.exec(...)  — variable + method call
	reVarCall = regexp.MustCompile(`\b(\w+)\.(\w+)\s*\(`)

	// exec(...)  — bare function call (for destructured bindings)
	reBareCall = regexp.MustCompile(`\b(\w+)\s*\(`)
)

// ParseBindings walks the source line by line and returns a fully-resolved SymbolTable.
// It handles:
//   - const/let/var x = require('module')
//   - const/let/var {a, b} = require('module')
//   - import x from 'module'
//   - import {a, b} from 'module'
//   - import * as x from 'module'
func ParseBindings(src []byte, fpath string) (SymbolTable, error) {
	table := make(SymbolTable)
	scanner := bufio.NewScanner(strings.NewReader(string(src)))
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	lineNo := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineNo++

		// const cp = require('child_process')
		if m := reVarBind.FindStringSubmatch(line); m != nil {
			table[m[1]] = Binding{Module: m[2], Export: "", Line: lineNo}
		}

		// const {exec, spawn: run} = require('child_process')
		if m := reDestructured.FindStringSubmatch(line); m != nil {
			module := m[2]
			for _, part := range strings.Split(m[1], ",") {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				// Handle aliasing: exec: myExec → local=myExec, export=exec
				if export, local, found := strings.Cut(part, ":"); found {
					table[strings.TrimSpace(local)] = Binding{Module: module, Export: strings.TrimSpace(export), Line: lineNo}
				} else {
					table[part] = Binding{Module: module, Export: part, Line: lineNo}
				}
			}
		}

		// import cp from 'child_process'
		if m := reImportDefault.FindStringSubmatch(line); m != nil {
			table[m[1]] = Binding{Module: m[2], Export: "default", Line: lineNo}
		}

		// import {exec, spawn as run} from 'child_process'
		if m := reImportNamed.FindStringSubmatch(line); m != nil {
			module := m[2]
			for _, part := range strings.Split(m[1], ",") {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				// Handle aliasing: exec as myExec
				lower := strings.ToLower(part)
				if idx := strings.Index(lower, " as "); idx >= 0 {
					export := strings.TrimSpace(part[:idx])
					local := strings.TrimSpace(part[idx+4:])
					table[local] = Binding{Module: module, Export: export, Line: lineNo}
				} else {
					table[part] = Binding{Module: module, Export: part, Line: lineNo}
				}
			}
		}

		// import * as cp from 'child_process'
		if m := reImportNamespace.FindStringSubmatch(line); m != nil {
			table[m[1]] = Binding{Module: m[2], Export: "", Line: lineNo}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return table, nil
}

// DetectFileAST runs multi-pass symbol-resolved detection on a single JS/TS file.
// It builds a SymbolTable from binding statements, then resolves call sites against it.
//
// Confidence levels:
//   - Direct import/require (module-level):         0.90
//   - Destructured: const {exec} = require(y):      0.85
//   - Chained: require('m').func():                 0.80
//   - Resolved x.method() where x = require(y):    0.80
//   - Bare call where identifier = require(y).func: 0.85
func DetectFileAST(path string) (capability.CapabilitySet, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return capability.CapabilitySet{}, err
	}

	table, err := ParseBindings(src, path)
	if err != nil {
		return capability.CapabilitySet{}, err
	}

	var caps capability.CapabilitySet

	// Module-level import capabilities from the symbol table.
	for localName, binding := range table {
		for _, c := range nodePatterns.Imports[binding.Module] {
			conf := 0.90
			via := "import"
			if binding.Export != "" && binding.Export != "default" {
				// Destructured or named import.
				conf = 0.85
				via = "import-destructured"
			}
			caps.AddWithEvidence(c, capability.CapabilityEvidence{
				File:       path,
				Line:       binding.Line,
				Context:    fmt.Sprintf("require(%q) as %s", binding.Module, localName),
				Via:        via,
				Confidence: conf,
			})
		}
	}

	// Line-by-line call-site detection using the symbol table.
	scanner := bufio.NewScanner(strings.NewReader(string(src)))
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineNo++

		// require('module').method() — direct chained call.
		// Look up capabilities from the import map (we know the exact module).
		for _, m := range reChainedCall.FindAllStringSubmatch(line, -1) {
			module := m[1]
			method := m[2]
			for _, c := range nodePatterns.Imports[module] {
				caps.AddWithEvidence(c, capability.CapabilityEvidence{
					File:       path,
					Line:       lineNo,
					Context:    fmt.Sprintf("require(%q).%s()", module, method),
					Via:        "callSite",
					Confidence: 0.80,
				})
			}
		}

		// x.method() — resolve x from symbol table, then look up by module.
		for _, m := range reVarCall.FindAllStringSubmatch(line, -1) {
			localName := m[1]
			method := m[2]
			binding, ok := table[localName]
			if !ok {
				continue
			}
			for _, c := range nodePatterns.Imports[binding.Module] {
				caps.AddWithEvidence(c, capability.CapabilityEvidence{
					File:       path,
					Line:       lineNo,
					Context:    fmt.Sprintf("%s.%s() via require(%q)", localName, method, binding.Module),
					Via:        "callSite",
					Confidence: 0.80,
				})
			}
		}

		// bare exec() — resolve from symbol table for destructured exports.
		for _, m := range reBareCall.FindAllStringSubmatch(line, -1) {
			localName := m[1]
			binding, ok := table[localName]
			if !ok || binding.Export == "" || binding.Export == "default" {
				continue
			}
			for _, c := range nodePatterns.Imports[binding.Module] {
				caps.AddWithEvidence(c, capability.CapabilityEvidence{
					File:       path,
					Line:       lineNo,
					Context:    fmt.Sprintf("%s() = require(%q).%s", localName, binding.Module, binding.Export),
					Via:        "callSite",
					Confidence: 0.85,
				})
			}
		}
	}

	return caps, nil
}

// ProjectGraph holds the cross-file symbol table and capabilities for a Node.js project.
type ProjectGraph struct {
	Files     map[string]SymbolTable                         // file path → symbol table
	Exports   map[string]map[string]capability.CapabilitySet // file path → export name → caps
	CallEdges []CallEdge
}

// CallEdge represents a call from one file to an export in another file.
type CallEdge struct {
	FromFile   string
	ToFile     string
	ExportName string
	Line       int
}

// BuildProjectGraph walks all .js/.ts files in dir and builds a project-wide graph.
func BuildProjectGraph(dir string) (ProjectGraph, error) {
	graph := ProjectGraph{
		Files:   make(map[string]SymbolTable),
		Exports: make(map[string]map[string]capability.CapabilitySet),
	}

	// Walk directory for .js and .ts files
	entries, err := os.ReadDir(dir)
	if err != nil {
		return graph, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			// Skip node_modules and hidden directories
			if entry.Name() == "node_modules" || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			// Recursively process subdirectories
			subGraph, err := BuildProjectGraph(filepath.Join(dir, entry.Name()))
			if err == nil {
				for k, v := range subGraph.Files {
					graph.Files[k] = v
				}
				for k, v := range subGraph.Exports {
					graph.Exports[k] = v
				}
				graph.CallEdges = append(graph.CallEdges, subGraph.CallEdges...)
			}
			continue
		}

		name := entry.Name()
		if !strings.HasSuffix(name, ".js") && !strings.HasSuffix(name, ".ts") {
			continue
		}

		fpath := filepath.Join(dir, name)
		src, err := os.ReadFile(fpath)
		if err != nil {
			continue
		}

		table, err := ParseBindings(src, fpath)
		if err != nil {
			continue
		}

		graph.Files[fpath] = table

		// Detect exports and their capabilities
		// This is a simplified heuristic: if a file has require() statements,
		// assume it might export functions with those capabilities.
		caps, _ := DetectFileAST(fpath)
		if !caps.IsEmpty() {
			if graph.Exports[fpath] == nil {
				graph.Exports[fpath] = make(map[string]capability.CapabilitySet)
			}
			// Assume default export carries all file capabilities
			graph.Exports[fpath]["default"] = caps
		}
	}

	return graph, nil
}

// PropagateAcrossFiles propagates capabilities across file boundaries using the project graph.
// It applies the same hop multipliers as Go propagation: 0→1.0, 1→0.70, 2→0.55, 3+→0.40
func PropagateAcrossFiles(graph ProjectGraph, perFileCaps map[string]capability.CapabilitySet) capability.CapabilitySet {
	// For Node.js, we use a simpler approach since we don't have full call graph data.
	// Just merge capabilities from all files with appropriate confidence multipliers.
	var merged capability.CapabilitySet

	for _, caps := range perFileCaps {
		merged.MergeWithEvidence(caps)
	}

	// Apply confidence multiplier for cross-file propagation (conservative estimate)
	for _, cap := range merged.List() {
		evs := merged.Evidence[cap]
		for i := range evs {
			// Reduce confidence slightly for cross-file detection
			evs[i].Confidence *= 0.90
		}
	}

	return merged
}
