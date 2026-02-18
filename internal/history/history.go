package history

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/1homsi/gorisk/internal/capability"
)

const fileName = ".gorisk-history.json"

type ModuleSnapshot struct {
	Module         string   `json:"module"`
	Version        string   `json:"version,omitempty"`
	RiskLevel      string   `json:"risk_level"`
	EffectiveScore int      `json:"effective_score"`
	Capabilities   []string `json:"capabilities,omitempty"`
}

type Snapshot struct {
	Timestamp string           `json:"timestamp"`
	Commit    string           `json:"commit,omitempty"`
	Modules   []ModuleSnapshot `json:"modules"`
}

type History struct {
	Snapshots []Snapshot `json:"snapshots"`
}

func Load(dir string) (*History, error) {
	path := filepath.Join(dir, fileName)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &History{}, nil
	}
	if err != nil {
		return nil, err
	}
	var h History
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, err
	}
	return &h, nil
}

func (h *History) Save(dir string) error {
	path := filepath.Join(dir, fileName)
	data, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func (h *History) Record(snap Snapshot) {
	if snap.Timestamp == "" {
		snap.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	h.Snapshots = append(h.Snapshots, snap)
	if len(h.Snapshots) > 100 {
		h.Snapshots = h.Snapshots[len(h.Snapshots)-100:]
	}
}

type ModuleDiff struct {
	Module string          `json:"module"`
	Old    *ModuleSnapshot `json:"old,omitempty"`
	New    *ModuleSnapshot `json:"new,omitempty"`
	Change string          `json:"change"`
}

func Diff(old, cur Snapshot) []ModuleDiff {
	oldByMod := make(map[string]ModuleSnapshot, len(old.Modules))
	for _, m := range old.Modules {
		oldByMod[m.Module] = m
	}
	newByMod := make(map[string]ModuleSnapshot, len(cur.Modules))
	for _, m := range cur.Modules {
		newByMod[m.Module] = m
	}

	var diffs []ModuleDiff

	for _, nm := range cur.Modules {
		om, existed := oldByMod[nm.Module]
		if !existed {
			nmCopy := nm
			diffs = append(diffs, ModuleDiff{Module: nm.Module, New: &nmCopy, Change: "added"})
			continue
		}
		omCopy := om
		nmCopy := nm
		change := "unchanged"
		switch {
		case capability.RiskValue(nm.RiskLevel) > capability.RiskValue(om.RiskLevel):
			change = "escalated"
		case capability.RiskValue(nm.RiskLevel) < capability.RiskValue(om.RiskLevel):
			change = "improved"
		case nm.EffectiveScore > om.EffectiveScore:
			change = "escalated"
		case nm.EffectiveScore < om.EffectiveScore:
			change = "improved"
		}
		diffs = append(diffs, ModuleDiff{Module: nm.Module, Old: &omCopy, New: &nmCopy, Change: change})
	}

	for _, om := range old.Modules {
		if _, exists := newByMod[om.Module]; !exists {
			omCopy2 := om
			diffs = append(diffs, ModuleDiff{Module: om.Module, Old: &omCopy2, Change: "removed"})
		}
	}

	return diffs
}
