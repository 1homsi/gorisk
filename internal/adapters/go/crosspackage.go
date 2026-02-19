package goadapter

import (
	"fmt"
	"go/ast"
	"go/types"
	"path/filepath"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
	"golang.org/x/tools/go/packages"
)

// PropagateAcrossPackages propagates capabilities across package boundaries within a module.
// It takes per-package function capabilities and call edges, then applies the same hop
// multipliers as intra-package propagation.
func PropagateAcrossPackages(
	pkgCaps map[string]map[string]ir.FunctionCaps,
	pkgEdges map[string][]ir.CallEdge,
) map[string]map[string]ir.FunctionCaps {
	// Build a unified function map: Symbol.String() → FunctionCaps
	allFuncs := make(map[string]ir.FunctionCaps)
	for _, funcs := range pkgCaps {
		for k, v := range funcs {
			allFuncs[k] = v
		}
	}

	// Collect all cross-package edges
	var allEdges []ir.CallEdge
	for _, edges := range pkgEdges {
		allEdges = append(allEdges, edges...)
	}

	// Propagate using the same algorithm as intra-package
	propagated := PropagateWithinPackage(allFuncs, allEdges)

	// Group back into per-package maps
	result := make(map[string]map[string]ir.FunctionCaps)
	for pkg := range pkgCaps {
		result[pkg] = make(map[string]ir.FunctionCaps)
	}

	for key, fc := range propagated {
		// Extract package from Symbol.String() (format is "pkg.Name")
		if pkg := fc.Symbol.Package; pkg != "" {
			if result[pkg] == nil {
				result[pkg] = make(map[string]ir.FunctionCaps)
			}
			result[pkg][key] = fc
		}
	}

	return result
}

// BuildModuleGraph loads all packages in the module at dir and builds a cross-package
// call graph using golang.org/x/tools/go/packages.
func BuildModuleGraph(dir string, g map[string]*Package) (map[string]map[string]ir.FunctionCaps, map[string][]ir.CallEdge, error) {
	// Load all packages in the module
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports,
		Dir:  dir,
	}

	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, nil, fmt.Errorf("load packages: %w", err)
	}

	// Continue despite package loading errors — partial analysis is better than none
	_ = packages.PrintErrors(pkgs)

	pkgCaps := make(map[string]map[string]ir.FunctionCaps)
	pkgEdges := make(map[string][]ir.CallEdge)

	for _, pkg := range pkgs {
		if len(pkg.Syntax) == 0 {
			continue
		}

		funcs := make(map[string]ir.FunctionCaps)
		var edges []ir.CallEdge

		fset := pkg.Fset

		// Build import alias map for this package
		importAliases := make(map[string]string)
		for path, imp := range pkg.Imports {
			localName := filepath.Base(path)
			if imp.Name != "" {
				localName = imp.Name
			}
			importAliases[localName] = path
		}

		for _, file := range pkg.Syntax {
			// Scan functions
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}

				callerSym := funcSymbolForPackage(fn, pkg.PkgPath)
				callerKey := callerSym.String()
				fc, exists := funcs[callerKey]
				if !exists {
					fc = ir.FunctionCaps{Symbol: callerSym}
				}

				// Scan call expressions
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}

					switch fun := call.Fun.(type) {
					case *ast.SelectorExpr:
						// pkg.Func() or obj.Method()
						if pkg.TypesInfo != nil && pkg.TypesInfo.Uses != nil {
							if sel, ok := pkg.TypesInfo.Selections[fun]; ok {
								// Method call
								if fn := sel.Obj(); fn != nil {
									calleePkg := ""
									if fn.Pkg() != nil {
										calleePkg = fn.Pkg().Path()
									}
									calleeSym := ir.Symbol{
										Package: calleePkg,
										Name:    fn.Name(),
										Kind:    "method",
									}
									edges = append(edges, ir.CallEdge{
										Caller: callerSym,
										Callee: calleeSym,
										File:   fset.Position(call.Pos()).Filename,
										Line:   fset.Position(call.Pos()).Line,
									})
								}
							} else if ident, ok := fun.X.(*ast.Ident); ok {
								// Package-level function call
								if obj := pkg.TypesInfo.Uses[ident]; obj != nil {
									if pkgName, ok := obj.(*types.PkgName); ok {
										calleePkg := pkgName.Imported().Path()
										funcName := fun.Sel.Name
										calleeSym := ir.Symbol{
											Package: calleePkg,
											Name:    funcName,
											Kind:    "func",
										}
										edges = append(edges, ir.CallEdge{
											Caller: callerSym,
											Callee: calleeSym,
											File:   fset.Position(call.Pos()).Filename,
											Line:   fset.Position(call.Pos()).Line,
										})

										// Also check for direct capability
										pkgShort := filepath.Base(calleePkg)
										pattern := pkgShort + "." + funcName
										for _, c := range GoPatterns.CallSites[pattern] {
											pos := fset.Position(call.Pos())
											fc.DirectCaps.AddWithEvidence(c, capability.CapabilityEvidence{
												File:       pos.Filename,
												Line:       pos.Line,
												Context:    pattern,
												Via:        "callSite",
												Confidence: 0.75,
											})
										}
									}
								}
							}
						}

					case *ast.Ident:
						// Bare function call within the same package
						if pkg.TypesInfo != nil && pkg.TypesInfo.Uses != nil {
							if obj := pkg.TypesInfo.Uses[fun]; obj != nil {
								if fn, ok := obj.(*types.Func); ok {
									calleePkg := pkg.PkgPath
									if fn.Pkg() != nil {
										calleePkg = fn.Pkg().Path()
									}
									calleeSym := ir.Symbol{
										Package: calleePkg,
										Name:    fn.Name(),
										Kind:    "func",
									}
									edges = append(edges, ir.CallEdge{
										Caller: callerSym,
										Callee: calleeSym,
										File:   fset.Position(call.Pos()).Filename,
										Line:   fset.Position(call.Pos()).Line,
									})
								}
							}
						}
					}
					return true
				})

				funcs[callerKey] = fc
			}
		}

		pkgCaps[pkg.PkgPath] = funcs
		pkgEdges[pkg.PkgPath] = edges
	}

	return pkgCaps, pkgEdges, nil
}

// funcSymbolForPackage builds a Symbol for an ast.FuncDecl with the given package path.
func funcSymbolForPackage(fn *ast.FuncDecl, pkgPath string) ir.Symbol {
	name := fn.Name.Name
	kind := "func"

	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		kind = "method"
		switch t := fn.Recv.List[0].Type.(type) {
		case *ast.StarExpr:
			if id, ok := t.X.(*ast.Ident); ok {
				name = id.Name + "." + name
			}
		case *ast.Ident:
			name = t.Name + "." + name
		}
	}

	return ir.Symbol{Package: pkgPath, Name: name, Kind: kind}
}

// Package is a minimal interface for the graph.Package type needed here.
type Package struct {
	ImportPath string
	Dir        string
	GoFiles    []string
	Module     *Module
}

// Module is a minimal interface for the graph.Module type needed here.
type Module struct {
	Path string
	Main bool
}
