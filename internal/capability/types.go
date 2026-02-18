package capability

import (
	"sort"
	"strings"
)

// Capability is the string name of a detected capability (e.g. "exec", "fs:read").
// Using a string alias instead of a bitflag removes the 16-capability ceiling and
// lets new languages introduce capabilities without touching this file.
type Capability = string

const (
	CapFSRead  Capability = "fs:read"
	CapFSWrite Capability = "fs:write"
	CapNetwork Capability = "network"
	CapExec    Capability = "exec"
	CapEnv     Capability = "env"
	CapUnsafe  Capability = "unsafe"
	CapCrypto  Capability = "crypto"
	CapReflect Capability = "reflect"
	CapPlugin  Capability = "plugin"
)

var capWeights = map[Capability]int{
	CapFSRead:  5,
	CapFSWrite: 10,
	CapNetwork: 15,
	CapExec:    20,
	CapEnv:     5,
	CapUnsafe:  25,
	CapCrypto:  5,
	CapReflect: 5,
	CapPlugin:  20,
}

// KnownCapability reports whether name is a recognised capability.
func KnownCapability(name string) bool {
	_, ok := capWeights[name]
	return ok
}

// RiskValue converts a risk-level string to a comparable integer (HIGH=3, MEDIUM=2, LOW=1).
func RiskValue(level string) int {
	switch strings.ToLower(level) {
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}

// CapabilitySet is a sorted, deduplicated set of capabilities with an accumulated score.
// Value copies are safe; mutations (Add, Merge) require a pointer receiver.
type CapabilitySet struct {
	caps  []string // sorted, deduplicated
	Score int
}

// Has reports whether cap is present.
func (cs CapabilitySet) Has(cap Capability) bool {
	i := sort.SearchStrings(cs.caps, cap)
	return i < len(cs.caps) && cs.caps[i] == cap
}

// IsEmpty reports whether the set contains no capabilities.
func (cs CapabilitySet) IsEmpty() bool { return len(cs.caps) == 0 }

// Add inserts cap into the set if not already present, accumulating its weight.
func (cs *CapabilitySet) Add(cap Capability) {
	i := sort.SearchStrings(cs.caps, cap)
	if i < len(cs.caps) && cs.caps[i] == cap {
		return
	}
	cs.Score += capWeights[cap]
	cs.caps = append(cs.caps, "")
	copy(cs.caps[i+1:], cs.caps[i:])
	cs.caps[i] = cap
}

// Merge adds all capabilities from other into cs.
func (cs *CapabilitySet) Merge(other CapabilitySet) {
	for _, c := range other.caps {
		cs.Add(c)
	}
}

// List returns a sorted copy of the capability names.
func (cs CapabilitySet) List() []string {
	if len(cs.caps) == 0 {
		return nil
	}
	out := make([]string, len(cs.caps))
	copy(out, cs.caps)
	return out
}

// RiskLevel returns "HIGH", "MEDIUM", or "LOW" based on the accumulated score.
func (cs CapabilitySet) RiskLevel() string {
	switch {
	case cs.Score >= 30:
		return "HIGH"
	case cs.Score >= 10:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// String returns a comma-separated list of capability names.
func (cs CapabilitySet) String() string {
	return strings.Join(cs.List(), ", ")
}
