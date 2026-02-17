package capability

import "strings"

type Capability uint16

const (
	CapFSRead Capability = 1 << iota
	CapFSWrite
	CapNetwork
	CapExec
	CapEnv
	CapUnsafe
	CapCrypto
	CapReflect
	CapPlugin
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

var capNames = map[Capability]string{
	CapFSRead:  "fs:read",
	CapFSWrite: "fs:write",
	CapNetwork: "network",
	CapExec:    "exec",
	CapEnv:     "env",
	CapUnsafe:  "unsafe",
	CapCrypto:  "crypto",
	CapReflect: "reflect",
	CapPlugin:  "plugin",
}

type CapabilitySet struct {
	Caps  Capability
	Score int
}

func (cs CapabilitySet) Has(cap Capability) bool {
	return cs.Caps&cap != 0
}

func (cs *CapabilitySet) Add(cap Capability) {
	if cs.Caps&cap == 0 {
		cs.Caps |= cap
		cs.Score += capWeights[cap]
	}
}

func (cs *CapabilitySet) Merge(other CapabilitySet) {
	var c Capability = 1
	for c != 0 && c <= CapPlugin {
		if other.Caps&c != 0 {
			cs.Add(c)
		}
		c <<= 1
	}
}

func (cs CapabilitySet) List() []string {
	var out []string
	var c Capability = 1
	for c != 0 && c <= CapPlugin {
		if cs.Caps&c != 0 {
			if name, ok := capNames[c]; ok {
				out = append(out, name)
			}
		}
		c <<= 1
	}
	return out
}

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

func (cs CapabilitySet) String() string {
	return strings.Join(cs.List(), ", ")
}
