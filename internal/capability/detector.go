package capability

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
)

func DetectFile(fpath string, fset *token.FileSet) (CapabilitySet, error) {
	if fset == nil {
		fset = token.NewFileSet()
	}
	f, err := parser.ParseFile(fset, fpath, nil, 0)
	if err != nil {
		return CapabilitySet{}, err
	}

	var cs CapabilitySet

	importAliases := make(map[string]string)

	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		for _, c := range GoPatterns.Imports[path] {
			cs.Add(c)
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
		for _, c := range GoPatterns.CallSites[pkgShort+"."+funcName] {
			cs.Add(c)
		}
		return true
	})

	return cs, nil
}

func DetectPackage(dir string, goFiles []string) (CapabilitySet, error) {
	fset := token.NewFileSet()
	var cs CapabilitySet
	for _, f := range goFiles {
		fpath := filepath.Join(dir, f)
		fileCaps, err := DetectFile(fpath, fset)
		if err != nil {
			continue
		}
		cs.Merge(fileCaps)
	}
	return cs, nil
}
