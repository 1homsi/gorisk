package goadapter

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

// DetectFunctions parses goFiles in dir and returns per-function direct capability sets
// along with intra-package call edges for propagation.
//
// Confidence for resolved call sites is 0.75 (alias always resolved).
func DetectFunctions(dir string, goFiles []string) (map[string]ir.FunctionCaps, []ir.CallEdge, error) {
	fset := token.NewFileSet()
	funcs := make(map[string]ir.FunctionCaps)
	var edges []ir.CallEdge

	for _, goFile := range goFiles {
		fpath := filepath.Join(dir, goFile)
		f, err := parser.ParseFile(fset, fpath, nil, 0)
		if err != nil {
			continue
		}

		// Build import alias map (same logic as DetectFile).
		importAliases := make(map[string]string)
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			localName := filepath.Base(path)
			if imp.Name != nil {
				localName = imp.Name.Name
			}
			importAliases[localName] = path
		}

		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}

			callerSym := funcSymbol(fn)
			callerKey := callerSym.String()
			fc, exists := funcs[callerKey]
			if !exists {
				fc = ir.FunctionCaps{Symbol: callerSym}
			}

			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}

				switch fun := call.Fun.(type) {
				case *ast.SelectorExpr:
					// pkg.Func() call — resolve via import aliases.
					ident, ok := fun.X.(*ast.Ident)
					if !ok {
						return true
					}
					pkgAlias := ident.Name
					callFuncName := fun.Sel.Name

					pkgPath, known := importAliases[pkgAlias]
					if !known {
						return true
					}
					pkgShort := filepath.Base(pkgPath)
					pattern := pkgShort + "." + callFuncName
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

				case *ast.Ident:
					// Bare identifier call — may be an intra-package call.
					calleeName := fun.Name
					pos := fset.Position(call.Pos())
					edges = append(edges, ir.CallEdge{
						Caller: callerSym,
						Callee: ir.Symbol{Package: "", Name: calleeName, Kind: "func"},
						File:   pos.Filename,
						Line:   pos.Line,
					})
				}
				return true
			})

			funcs[callerKey] = fc
		}
	}

	return funcs, edges, nil
}

// funcSymbol builds a Symbol for an ast.FuncDecl.
func funcSymbol(fn *ast.FuncDecl) ir.Symbol {
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

	return ir.Symbol{Package: "", Name: name, Kind: kind}
}
