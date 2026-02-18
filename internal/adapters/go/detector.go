package goadapter

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
)

// DetectFile parses a single Go source file and returns its capability set with evidence.
func DetectFile(fpath string, fset *token.FileSet) (capability.CapabilitySet, error) {
	if fset == nil {
		fset = token.NewFileSet()
	}
	f, err := parser.ParseFile(fset, fpath, nil, 0)
	if err != nil {
		return capability.CapabilitySet{}, err
	}

	var cs capability.CapabilitySet

	importAliases := make(map[string]string)

	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		for _, c := range GoPatterns.Imports[path] {
			pos := fset.Position(imp.Path.Pos())
			cs.AddWithEvidence(c, capability.CapabilityEvidence{
				File:       pos.Filename,
				Line:       pos.Line,
				Context:    fmt.Sprintf("import %q", path),
				Via:        "import",
				Confidence: 0.90,
			})
		}
		localName := filepath.Base(path)
		if imp.Name != nil {
			localName = imp.Name.Name
		}
		importAliases[localName] = path
	}

	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		pkgAlias := ident.Name
		funcName := sel.Sel.Name

		pkgPath, known := importAliases[pkgAlias]
		if !known {
			return true
		}
		pkgShort := filepath.Base(pkgPath)
		pattern := pkgShort + "." + funcName
		for _, c := range GoPatterns.CallSites[pattern] {
			pos := fset.Position(call.Pos())
			cs.AddWithEvidence(c, capability.CapabilityEvidence{
				File:       pos.Filename,
				Line:       pos.Line,
				Context:    pattern,
				Via:        "callSite",
				Confidence: 0.60,
			})
		}
		return true
	})

	return cs, nil
}

// DetectPackage runs DetectFile over all Go files in a package directory,
// merging capabilities and evidence from each file.
func DetectPackage(dir string, goFiles []string) (capability.CapabilitySet, error) {
	fset := token.NewFileSet()
	var cs capability.CapabilitySet
	for _, f := range goFiles {
		fpath := filepath.Join(dir, f)
		fileCaps, err := DetectFile(fpath, fset)
		if err != nil {
			continue
		}
		cs.MergeWithEvidence(fileCaps)
	}
	return cs, nil
}
