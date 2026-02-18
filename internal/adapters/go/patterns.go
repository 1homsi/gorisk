package goadapter

import "github.com/1homsi/gorisk/internal/capability"

// GoPatterns holds the Go capability patterns loaded from languages/go.yaml.
var GoPatterns = capability.MustLoadPatterns("go")

// ImportCapabilities returns the capabilities associated with a Go import path.
func ImportCapabilities(importPath string) []capability.Capability {
	return GoPatterns.Imports[importPath]
}

// CallCapabilities returns the capabilities for a pkg.Func call pattern.
func CallCapabilities(pkgName, funcName string) []capability.Capability {
	return GoPatterns.CallSites[pkgName+"."+funcName]
}
