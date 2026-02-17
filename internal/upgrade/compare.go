package upgrade

import (
	"fmt"
	"go/types"

	"github.com/1homsi/gorisk/internal/report"
)

func diffScopes(oldPkg, newPkg *types.Package) []report.BreakingChange {
	var changes []report.BreakingChange

	if oldPkg == nil || newPkg == nil {
		return changes
	}

	oldScope := oldPkg.Scope()
	newScope := newPkg.Scope()

	for _, name := range oldScope.Names() {
		oldObj := oldScope.Lookup(name)
		if !oldObj.Exported() {
			continue
		}
		newObj := newScope.Lookup(name)
		if newObj == nil {
			changes = append(changes, report.BreakingChange{
				Kind:   "removed",
				Symbol: name,
				OldSig: objectSig(oldObj),
			})
			continue
		}
		if !types.Identical(oldObj.Type(), newObj.Type()) {
			changes = append(changes, report.BreakingChange{
				Kind:   "type_changed",
				Symbol: name,
				OldSig: objectSig(oldObj),
				NewSig: objectSig(newObj),
			})
		}
	}

	return changes
}

func objectSig(obj types.Object) string {
	switch o := obj.(type) {
	case *types.Func:
		return o.Type().(*types.Signature).String()
	case *types.TypeName:
		return fmt.Sprintf("type %s %s", o.Name(), o.Type().Underlying().String())
	case *types.Var:
		return fmt.Sprintf("var %s %s", o.Name(), o.Type().String())
	case *types.Const:
		return fmt.Sprintf("const %s %s", o.Name(), o.Type().String())
	default:
		return obj.Type().String()
	}
}
