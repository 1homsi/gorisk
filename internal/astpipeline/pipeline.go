package astpipeline

import (
	"fmt"

	clojureadapter "github.com/1homsi/gorisk/internal/adapters/clojure"
	cppadapter "github.com/1homsi/gorisk/internal/adapters/cpp"
	dartadapter "github.com/1homsi/gorisk/internal/adapters/dart"
	dotnetadapter "github.com/1homsi/gorisk/internal/adapters/dotnet"
	elixiradapter "github.com/1homsi/gorisk/internal/adapters/elixir"
	erlangadapter "github.com/1homsi/gorisk/internal/adapters/erlang"
	goadapter "github.com/1homsi/gorisk/internal/adapters/go"
	haskelladapter "github.com/1homsi/gorisk/internal/adapters/haskell"
	javaadapter "github.com/1homsi/gorisk/internal/adapters/java"
	juliaadapter "github.com/1homsi/gorisk/internal/adapters/julia"
	kotlinadapter "github.com/1homsi/gorisk/internal/adapters/kotlin"
	luaadapter "github.com/1homsi/gorisk/internal/adapters/lua"
	nodeadapter "github.com/1homsi/gorisk/internal/adapters/node"
	ocamladapter "github.com/1homsi/gorisk/internal/adapters/ocaml"
	perladapter "github.com/1homsi/gorisk/internal/adapters/perl"
	pythonadapter "github.com/1homsi/gorisk/internal/adapters/python"
	radapter "github.com/1homsi/gorisk/internal/adapters/r"
	rubyadapter "github.com/1homsi/gorisk/internal/adapters/ruby"
	rustadapter "github.com/1homsi/gorisk/internal/adapters/rust"
	scalaadapter "github.com/1homsi/gorisk/internal/adapters/scala"
	swiftadapter "github.com/1homsi/gorisk/internal/adapters/swift"
	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/interproc"
	"github.com/1homsi/gorisk/internal/ir"
)

// Result is a command-friendly wrapper around interprocedural analysis outputs.
type Result struct {
	Bundle        interproc.ResultBundle
	UsedInterproc bool
	Reason        string
}

// Analyze tries to run interprocedural AST analysis for the given language.
// It always returns a Result; callers should fall back when UsedInterproc is false.
func Analyze(dir, lang string, g *graph.DependencyGraph) Result {
	irGraph, err := buildIR(dir, lang, g)
	if err != nil {
		return Result{UsedInterproc: false, Reason: err.Error()}
	}
	if len(irGraph.Functions) == 0 {
		return Result{UsedInterproc: false, Reason: "no function-level IR available"}
	}
	bundle, err := interproc.RunBundle(irGraph, interproc.DefaultOptions())
	if err != nil {
		return Result{UsedInterproc: false, Reason: err.Error()}
	}
	return Result{Bundle: bundle, UsedInterproc: true, Reason: "interproc enabled"}
}

func buildIR(dir, lang string, g *graph.DependencyGraph) (ir.IRGraph, error) {
	switch lang {
	case "go":
		return goadapter.BuildIRGraph(dir, g)
	case "node":
		return nodeadapter.BuildIRGraph(g), nil
	case "python":
		return pythonadapter.BuildIRGraph(g), nil
	case "ruby":
		return rubyadapter.BuildIRGraph(g), nil
	case "lua":
		return luaadapter.BuildIRGraph(g), nil
	case "java":
		return javaadapter.BuildIRGraph(g), nil
	case "kotlin":
		return kotlinadapter.BuildIRGraph(g), nil
	case "scala":
		return scalaadapter.BuildIRGraph(g), nil
	case "rust":
		return rustadapter.BuildIRGraph(g), nil
	case "haskell":
		return haskelladapter.BuildIRGraph(g), nil
	case "ocaml":
		return ocamladapter.BuildIRGraph(g), nil
	case "elixir":
		return elixiradapter.BuildIRGraph(g), nil
	case "erlang":
		return erlangadapter.BuildIRGraph(g), nil
	case "clojure":
		return clojureadapter.BuildIRGraph(g), nil
	case "swift":
		return swiftadapter.BuildIRGraph(g), nil
	case "dart":
		return dartadapter.BuildIRGraph(g), nil
	case "dotnet":
		return dotnetadapter.BuildIRGraph(g), nil
	case "cpp":
		return cppadapter.BuildIRGraph(g), nil
	case "julia":
		return juliaadapter.BuildIRGraph(g), nil
	case "r":
		return radapter.BuildIRGraph(g), nil
	case "perl":
		return perladapter.BuildIRGraph(g), nil
	default:
		return ir.IRGraph{}, fmt.Errorf("interproc not available for lang %q", lang)
	}
}
