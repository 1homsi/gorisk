package analyzer

import (
	"fmt"
	"os"
	"path/filepath"

	goadapter "github.com/1homsi/gorisk/internal/adapters/go"
	nodeadapter "github.com/1homsi/gorisk/internal/adapters/node"
	phpadapter "github.com/1homsi/gorisk/internal/adapters/php"
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
}

// FeaturesFor returns the feature implementations for the given language.
// lang may be "auto", "go", "node", or "php".
func FeaturesFor(lang, dir string) (LangFeatures, error) {
	if lang == "auto" || lang == "" {
		lang = detect(dir)
		if lang == "multi" {
			lang = "go" // multi-repo: default to go for non-graph features
		}
	}
	f, ok := registry[lang]
	if !ok {
		return LangFeatures{}, fmt.Errorf("unknown language %q; choose auto|go|node|php", lang)
	}
	return f, nil
}

// Analyzer loads a dependency graph for a project directory.
type Analyzer interface {
	Name() string
	Load(dir string) (*graph.DependencyGraph, error)
}

// ForLang returns an Analyzer for the given language specifier.
// lang may be "auto", "go", "node", or "php".
// "auto" detects from go.mod / package.json / composer.json presence.
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
	case "multi":
		return &multiAnalyzer{}, nil
	default:
		return nil, fmt.Errorf("unknown language %q; choose auto|go|node|php", lang)
	}
}

func detect(dir string) string {
	hasGoMod := fileExists(filepath.Join(dir, "go.mod"))
	hasPkgJSON := fileExists(filepath.Join(dir, "package.json"))
	hasComposerJSON := fileExists(filepath.Join(dir, "composer.json"))
	hasComposerLock := fileExists(filepath.Join(dir, "composer.lock"))
	switch {
	case hasGoMod && hasPkgJSON:
		return "multi"
	case hasGoMod:
		return "go"
	case hasPkgJSON:
		return "node"
	case hasComposerJSON || hasComposerLock:
		return "php"
	default:
		return "go"
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
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
