package impact

import (
	"testing"

	"github.com/1homsi/gorisk/internal/graph"
)

func buildTestGraph() *graph.DependencyGraph {
	g := graph.NewDependencyGraph()

	libMod := &graph.Module{Path: "example.com/lib", Version: "v1.0.0"}
	appMod := &graph.Module{Path: "example.com/app", Main: true}

	libPkg := &graph.Package{ImportPath: "example.com/lib/core", Module: libMod, Name: "core"}
	appPkg := &graph.Package{ImportPath: "example.com/app/cmd", Module: appMod, Name: "main"}

	libMod.Packages = []*graph.Package{libPkg}
	appMod.Packages = []*graph.Package{appPkg}

	g.Modules["example.com/lib"] = libMod
	g.Modules["example.com/app"] = appMod
	g.Packages["example.com/lib/core"] = libPkg
	g.Packages["example.com/app/cmd"] = appPkg

	g.Edges["example.com/app/cmd"] = []string{"example.com/lib/core"}

	return g
}

func TestComputeAffectedPackages(t *testing.T) {
	g := buildTestGraph()
	r := Compute(g, "example.com/lib")

	if len(r.AffectedPackages) != 1 || r.AffectedPackages[0] != "example.com/app/cmd" {
		t.Errorf("expected app/cmd to be affected, got %v", r.AffectedPackages)
	}
}

func TestComputeAffectedMains(t *testing.T) {
	g := buildTestGraph()
	r := Compute(g, "example.com/lib")

	if len(r.AffectedMains) != 1 || r.AffectedMains[0] != "example.com/app/cmd" {
		t.Errorf("expected app/cmd in affected mains, got %v", r.AffectedMains)
	}
}

func TestComputeDepth(t *testing.T) {
	g := buildTestGraph()
	r := Compute(g, "example.com/lib")

	if r.Depth != 1 {
		t.Errorf("expected depth 1, got %d", r.Depth)
	}
}

func TestComputeUnknownModule(t *testing.T) {
	g := buildTestGraph()
	r := Compute(g, "example.com/unknown")

	if len(r.AffectedPackages) != 0 {
		t.Errorf("unknown module should produce no affected packages, got %v", r.AffectedPackages)
	}
}

func TestIsMain(t *testing.T) {
	mainPkg := &graph.Package{Name: "main"}
	libPkg := &graph.Package{Name: "mylib"}

	if !isMain(mainPkg) {
		t.Error("package named 'main' should be detected as main")
	}
	if isMain(libPkg) {
		t.Error("package named 'mylib' should not be detected as main")
	}
	if isMain(nil) {
		t.Error("nil package should not be detected as main")
	}
}
