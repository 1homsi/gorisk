package goadapter

import (
	"fmt"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/ir"
)

// hopMultiplier returns the confidence multiplier for the given propagation hop count.
//
//	hop 0 (direct)  → 1.00
//	hop 1           → 0.70
//	hop 2           → 0.55
//	hop 3+          → 0.40
func hopMultiplier(hops int) float64 {
	switch {
	case hops <= 0:
		return 1.00
	case hops == 1:
		return 0.70
	case hops == 2:
		return 0.55
	default:
		return 0.40
	}
}

// PropagateWithinPackage propagates capabilities from callees to callers
// for all edges that reference functions present in funcs.
//
// Each pass propagates one additional hop. Up to 3 passes are run to cover
// call chains of depth 1-3+.
func PropagateWithinPackage(
	funcs map[string]ir.FunctionCaps,
	calls []ir.CallEdge,
) map[string]ir.FunctionCaps {
	result := cloneFuncs(funcs)

	// Pass i propagates callee capabilities at hop depth i+1.
	// Pass 0: callee.DirectCaps → caller.TransitiveCaps  (hop 1)
	// Pass 1: callee.TransitiveCaps → caller.TransitiveCaps (hop 2)
	// Pass 2+: same with hop 3+ multiplier (0.40)
	const maxPasses = 3
	for pass := range maxPasses {
		hops := pass + 1
		mult := hopMultiplier(hops)
		changed := false

		for _, edge := range calls {
			calleeKey := edge.Callee.String()
			callerKey := edge.Caller.String()

			callee, ok := result[calleeKey]
			if !ok {
				continue
			}
			caller, ok := result[callerKey]
			if !ok {
				continue
			}

			// On the first pass propagate direct caps; on subsequent passes
			// propagate transitive caps (which accumulate across passes).
			var src capability.CapabilitySet
			if pass == 0 {
				src = callee.DirectCaps
			} else {
				src = callee.TransitiveCaps
			}

			for _, cap := range src.List() {
				evs := src.Evidence[cap]
				for _, ev := range evs {
					newEv := capability.CapabilityEvidence{
						File:       ev.File,
						Line:       ev.Line,
						Context:    fmt.Sprintf("%s (transitive via %s)", ev.Context, calleeKey),
						Via:        "transitive",
						Confidence: ev.Confidence * mult,
					}
					before := caller.TransitiveCaps.Score
					caller.TransitiveCaps.AddWithEvidence(cap, newEv)
					if caller.TransitiveCaps.Score != before {
						changed = true
					}
				}
			}
			result[callerKey] = caller
		}

		if !changed {
			break
		}
	}

	return result
}

// cloneFuncs makes a shallow clone of the funcs map (CapabilitySet values are copied by value).
func cloneFuncs(funcs map[string]ir.FunctionCaps) map[string]ir.FunctionCaps {
	out := make(map[string]ir.FunctionCaps, len(funcs))
	for k, v := range funcs {
		out[k] = v
	}
	return out
}
