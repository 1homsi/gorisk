package reachability

import (
	"go/token"

	goadapter "github.com/1homsi/gorisk/internal/adapters/go"
	"github.com/1homsi/gorisk/internal/capability"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func analyzeGo(dir string) ([]ReachabilityReport, error) {
	cfg := &packages.Config{
		Dir: dir,
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedCompiledGoFiles |
			packages.NeedImports |
			packages.NeedDeps |
			packages.NeedTypes |
			packages.NeedSyntax |
			packages.NeedTypesInfo,
		Fset: token.NewFileSet(),
	}

	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, err
	}

	prog, ssaPkgs := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics)
	prog.Build()

	var mains []*ssa.Package
	for _, p := range ssaPkgs {
		if p != nil && p.Pkg.Name() == "main" {
			mains = append(mains, p)
		}
	}

	reachablePkgs := make(map[string]bool)

	if len(mains) > 0 {
		var roots []*ssa.Function
		for _, m := range mains {
			if f := m.Func("main"); f != nil {
				roots = append(roots, f)
			}
			if f := m.Func("init"); f != nil {
				roots = append(roots, f)
			}
		}

		if len(roots) > 0 {
			result := rta.Analyze(roots, true)
			for fn := range result.Reachable {
				if fn.Package() != nil {
					reachablePkgs[fn.Package().Pkg.Path()] = true
				}
			}
			result.CallGraph.DeleteSyntheticNodes()
			callgraph.GraphVisitEdges(result.CallGraph, func(e *callgraph.Edge) error {
				if e.Callee.Func.Package() != nil {
					reachablePkgs[e.Callee.Func.Package().Pkg.Path()] = true
				}
				return nil
			})
		}
	}

	seen := make(map[string]bool)
	var reports []ReachabilityReport

	for _, lp := range pkgs {
		packages.Visit([]*packages.Package{lp}, func(p *packages.Package) bool {
			if seen[p.PkgPath] || p.PkgPath == "" {
				return false
			}
			seen[p.PkgPath] = true

			var cs capability.CapabilitySet
			for imp := range p.Imports {
				for _, c := range goadapter.ImportCapabilities(imp) {
					cs.Add(c)
				}
			}

			if cs.Score == 0 {
				return true
			}

			reports = append(reports, ReachabilityReport{
				Package:       p.PkgPath,
				ReachableCaps: cs,
				Reachable:     reachablePkgs[p.PkgPath],
			})
			return true
		}, nil)
	}

	return reports, nil
}
