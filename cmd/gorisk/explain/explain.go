package explain

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/1homsi/gorisk/internal/analyzer"
	"github.com/1homsi/gorisk/internal/capability"
)

type evidenceEntry struct {
	Package    string
	Module     string
	Capability string
	Evidence   []capability.CapabilityEvidence
}

func Run(args []string) int {
	fs := flag.NewFlagSet("explain", flag.ExitOnError)
	capFilter := fs.String("cap", "", "filter to a specific capability (e.g. exec, network)")
	jsonOut := fs.Bool("json", false, "JSON output")
	lang := fs.String("lang", "auto", "language analyzer: auto|go|node")
	fs.Parse(args)

	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	a, err := analyzer.ForLang(*lang, dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	g, err := a.Load(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load graph:", err)
		return 2
	}

	var entries []evidenceEntry
	for _, pkg := range g.Packages {
		if pkg.Module == nil || pkg.Module.Main {
			continue
		}
		for _, cap := range pkg.Capabilities.List() {
			if *capFilter != "" && cap != *capFilter {
				continue
			}
			evs := pkg.Capabilities.Evidence[cap]
			entries = append(entries, evidenceEntry{
				Package:    pkg.ImportPath,
				Module:     pkg.Module.Path,
				Capability: cap,
				Evidence:   evs,
			})
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Capability != entries[j].Capability {
			return entries[i].Capability < entries[j].Capability
		}
		if entries[i].Module != entries[j].Module {
			return entries[i].Module < entries[j].Module
		}
		return entries[i].Package < entries[j].Package
	})

	if *jsonOut {
		return printJSON(entries)
	}
	return printText(entries, dir)
}

func printJSON(entries []evidenceEntry) int {
	type jsonEv struct {
		File       string  `json:"file"`
		Line       int     `json:"line,omitempty"`
		Context    string  `json:"context,omitempty"`
		Via        string  `json:"via,omitempty"`
		Confidence float64 `json:"confidence,omitempty"`
	}
	type jsonEntry struct {
		Package    string   `json:"package"`
		Module     string   `json:"module"`
		Capability string   `json:"capability"`
		Evidence   []jsonEv `json:"evidence"`
	}
	var out []jsonEntry
	for _, e := range entries {
		jevs := make([]jsonEv, 0, len(e.Evidence))
		for _, ev := range e.Evidence {
			jevs = append(jevs, jsonEv{
				File:       ev.File,
				Line:       ev.Line,
				Context:    ev.Context,
				Via:        ev.Via,
				Confidence: ev.Confidence,
			})
		}
		out = append(out, jsonEntry{
			Package:    e.Package,
			Module:     e.Module,
			Capability: e.Capability,
			Evidence:   jevs,
		})
	}
	if out == nil {
		out = []jsonEntry{}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(out)
	return 0
}

func printText(entries []evidenceEntry, cwd string) int {
	const (
		bold   = "\033[1m"
		cyan   = "\033[36m"
		yellow = "\033[33m"
		gray   = "\033[90m"
		reset  = "\033[0m"
	)

	if len(entries) == 0 {
		fmt.Println("no capabilities found")
		return 0
	}

	fmt.Fprintf(os.Stdout, "%s%s=== Capability Evidence ===%s\n\n", bold, cyan, reset)

	// Group by capability
	type modGroup struct {
		modules map[string][]evidenceEntry
		order   []string
	}
	capGroups := make(map[string]*modGroup)
	capOrder := []string{}

	for _, e := range entries {
		if _, ok := capGroups[e.Capability]; !ok {
			capGroups[e.Capability] = &modGroup{modules: make(map[string][]evidenceEntry)}
			capOrder = append(capOrder, e.Capability)
		}
		cg := capGroups[e.Capability]
		if _, exists := cg.modules[e.Module]; !exists {
			cg.order = append(cg.order, e.Module)
		}
		cg.modules[e.Module] = append(cg.modules[e.Module], e)
	}

	for _, capName := range capOrder {
		cg := capGroups[capName]
		fmt.Fprintf(os.Stdout, "%s%s%s\n", bold, capName, reset)
		for _, modPath := range cg.order {
			fmt.Fprintf(os.Stdout, "  %s%s%s\n", yellow, modPath, reset)
			pkgEntries := cg.modules[modPath]
			for _, entry := range pkgEntries {
				if len(entry.Evidence) == 0 {
					fmt.Fprintf(os.Stdout, "    %s(no evidence recorded)%s\n", gray, reset)
					continue
				}
				for _, ev := range entry.Evidence {
					file := ev.File
					if cwd != "" {
						if rel, err := filepath.Rel(cwd, ev.File); err == nil && !strings.HasPrefix(rel, "..") {
							file = rel
						}
					}
					loc := file
					if ev.Line > 0 {
						loc = fmt.Sprintf("%s:%d", file, ev.Line)
					}
					confStr := ""
					if ev.Confidence > 0 {
						confStr = fmt.Sprintf("  %d%%", int(ev.Confidence*100))
					}
					fmt.Fprintf(os.Stdout, "    %-55s  %s%-12s%s  [%s%s]\n",
						loc, gray, ev.Context, reset, ev.Via, confStr)
				}
			}
		}
		fmt.Fprintln(os.Stdout)
	}
	return 0
}
