package capability

import (
	"fmt"

	"github.com/1homsi/gorisk/languages"
	"gopkg.in/yaml.v3"
)

// PatternSet holds the resolved capability-detection patterns for a language.
// It is loaded from a languages/*.yaml file via LoadPatterns.
type PatternSet struct {
	Name      string
	Imports   map[string][]Capability // import path  → capabilities
	CallSites map[string][]Capability // call pattern → capabilities
}

// rawPatternSet mirrors the YAML structure before capability names are resolved.
type rawPatternSet struct {
	Name      string              `yaml:"name"`
	Imports   map[string][]string `yaml:"imports"`
	CallSites map[string][]string `yaml:"call_sites"`
}

// LoadPatterns reads and validates languages/<lang>.yaml from the embedded FS.
// Capability name strings are validated against the known taxonomy and converted
// to typed Capability values — unknown names cause an early error.
func LoadPatterns(lang string) (*PatternSet, error) {
	data, err := languages.FS.ReadFile(lang + ".yaml")
	if err != nil {
		return nil, fmt.Errorf("load patterns for %q: %w", lang, err)
	}

	var raw rawPatternSet
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse %s.yaml: %w", lang, err)
	}

	ps := &PatternSet{
		Name:      raw.Name,
		Imports:   make(map[string][]Capability, len(raw.Imports)),
		CallSites: make(map[string][]Capability, len(raw.CallSites)),
	}

	for path, names := range raw.Imports {
		caps, err := resolveCapNames(names, lang+".yaml imports."+path)
		if err != nil {
			return nil, err
		}
		ps.Imports[path] = caps
	}

	for pattern, names := range raw.CallSites {
		caps, err := resolveCapNames(names, lang+".yaml call_sites."+pattern)
		if err != nil {
			return nil, err
		}
		ps.CallSites[pattern] = caps
	}

	return ps, nil
}

// MustLoadPatterns is like LoadPatterns but panics on error.
// Safe to call at package-init time since the YAML is embedded at compile time.
func MustLoadPatterns(lang string) *PatternSet {
	ps, err := LoadPatterns(lang)
	if err != nil {
		panic(fmt.Sprintf("gorisk: %v", err))
	}
	return ps
}

// resolveCapNames validates capability name strings against the known taxonomy
// and returns them as typed Capability values.
func resolveCapNames(names []string, location string) ([]Capability, error) {
	caps := make([]Capability, 0, len(names))
	for _, name := range names {
		if !KnownCapability(name) {
			return nil, fmt.Errorf("unknown capability %q in %s", name, location)
		}
		caps = append(caps, name)
	}
	return caps, nil
}
