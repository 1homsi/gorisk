// Package versiondiff compares lockfile states to compute per-package risk deltas.
package versiondiff

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// PackageDiff describes a risk-relevant change for a single package.
type PackageDiff struct {
	Package    string
	ChangeType string // "new" | "escalated" | "new_install_script" | "blast_radius"
	OldCaps    []string
	NewCaps    []string
	RiskDelta  float64
}

// DiffReport summarises risk changes between two lockfile states.
type DiffReport struct {
	Base             string
	NewPackages      []PackageDiff
	Escalations      []PackageDiff
	BlastRadiusDelta int     // change in affected-package count
	Score            float64 // 0-20
}

// Compute compares the current lockfile in dir against base (a git ref or lockfile path).
// lang must be "auto", "go", or "node".
func Compute(dir, base, lang string) (DiffReport, error) {
	if base == "" {
		return DiffReport{Score: 0}, nil
	}

	resolved, err := resolveLang(dir, lang)
	if err != nil {
		return DiffReport{}, err
	}

	switch resolved {
	case "go":
		return computeGo(dir, base)
	case "node":
		return computeNode(dir, base)
	default:
		return DiffReport{}, fmt.Errorf("unsupported language: %s", resolved)
	}
}

func resolveLang(dir, lang string) (string, error) {
	if lang != "auto" {
		return lang, nil
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
		return "go", nil
	}
	for _, lf := range []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml"} {
		if _, err := os.Stat(filepath.Join(dir, lf)); err == nil {
			return "node", nil
		}
	}
	return "", fmt.Errorf("could not detect language in %s", dir)
}

// ---------------------------------------------------------------------------
// Go implementation
// ---------------------------------------------------------------------------

func computeGo(dir, base string) (DiffReport, error) {
	r := DiffReport{Base: base}

	// Read current go.mod requires.
	currentMods, err := readGoModRequires(filepath.Join(dir, "go.mod"))
	if err != nil {
		return r, fmt.Errorf("read current go.mod: %w", err)
	}

	// Read base go.mod requires (from git ref or file path).
	baseData, err := readBase(dir, base, "go.mod")
	if err != nil {
		return r, fmt.Errorf("read base go.mod (%s): %w", base, err)
	}
	baseMods, err := readGoModRequiresFromBytes(baseData)
	if err != nil {
		return r, fmt.Errorf("parse base go.mod: %w", err)
	}

	// New packages.
	for mod, ver := range currentMods {
		if _, existed := baseMods[mod]; !existed {
			caps := inferGoCaps(mod)
			level := capsToLevel(caps)
			delta := levelDelta(level, "")
			pd := PackageDiff{
				Package:    mod + "@" + ver,
				ChangeType: "new",
				NewCaps:    caps,
				RiskDelta:  delta,
			}
			r.NewPackages = append(r.NewPackages, pd)
		}
	}

	// Escalations: same module, different version with higher caps.
	for mod, newVer := range currentMods {
		if _, existed := baseMods[mod]; existed {
			oldCaps := inferGoCaps(mod)
			newCaps := inferGoCaps(mod)
			// For now version-based cap inference is identical;
			// real escalation detection would require semantic analysis.
			oldLevel := capsToLevel(oldCaps)
			newLevel := capsToLevel(newCaps)
			_ = oldLevel
			_ = newLevel
			_ = newVer
		}
	}

	r.Score = computeScore(r)
	return r, nil
}

func readGoModRequires(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return readGoModRequiresFromBytes(data)
}

func readGoModRequiresFromBytes(data []byte) (map[string]string, error) {
	mods := make(map[string]string)
	inRequire := false

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case line == "require (":
			inRequire = true
		case inRequire && line == ")":
			inRequire = false
		case strings.HasPrefix(line, "require "):
			parts := strings.Fields(strings.TrimPrefix(line, "require "))
			if len(parts) >= 2 {
				mods[parts[0]] = parts[1]
			}
		case inRequire && line != "" && !strings.HasPrefix(line, "//"):
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				mods[parts[0]] = parts[1]
			}
		}
	}
	return mods, nil
}

// inferGoCaps returns a rough capability set for a Go module path based on its name.
// This is a heuristic for diff scoring; the real capability set comes from the analyzer.
func inferGoCaps(mod string) []string {
	lower := strings.ToLower(mod)
	var caps []string
	if strings.Contains(lower, "exec") || strings.Contains(lower, "process") {
		caps = append(caps, "exec")
	}
	if strings.Contains(lower, "net") || strings.Contains(lower, "http") || strings.Contains(lower, "grpc") {
		caps = append(caps, "network")
	}
	if strings.Contains(lower, "crypto") || strings.Contains(lower, "tls") {
		caps = append(caps, "crypto")
	}
	return caps
}

// ---------------------------------------------------------------------------
// Node implementation
// ---------------------------------------------------------------------------

func computeNode(dir, base string) (DiffReport, error) {
	r := DiffReport{Base: base}

	// Detect which lockfile is in use.
	lockfile, reader, err := detectNodeLockfile(dir)
	if err != nil {
		return r, err
	}

	// Read current lockfile packages.
	currentPkgs, err := reader(filepath.Join(dir, lockfile))
	if err != nil {
		return r, fmt.Errorf("read current %s: %w", lockfile, err)
	}

	// Read base lockfile (same filename from git ref or path).
	baseData, err := readBase(dir, base, lockfile)
	if err != nil {
		return r, fmt.Errorf("read base %s (%s): %w", lockfile, base, err)
	}
	basePkgs, err := nodePackagesFromBytes(lockfile, baseData)
	if err != nil {
		return r, fmt.Errorf("parse base %s: %w", lockfile, err)
	}

	// New packages.
	for name, ver := range currentPkgs {
		if _, existed := basePkgs[name]; !existed {
			caps := inferNodeCaps(name)
			level := capsToLevel(caps)
			delta := levelDelta(level, "")
			pd := PackageDiff{
				Package:    name + "@" + ver,
				ChangeType: "new",
				NewCaps:    caps,
				RiskDelta:  delta,
			}
			r.NewPackages = append(r.NewPackages, pd)
		}
	}

	// Escalations: same package, new version that adds higher-risk caps.
	for name, newVer := range currentPkgs {
		oldVer, existed := basePkgs[name]
		if !existed || oldVer == newVer {
			continue
		}
		oldCaps := inferNodeCaps(name)
		newCaps := inferNodeCaps(name)
		oldLevel := capsToLevel(oldCaps)
		newLevel := capsToLevel(newCaps)
		if riskVal(newLevel) > riskVal(oldLevel) {
			delta := levelDelta(newLevel, oldLevel)
			r.Escalations = append(r.Escalations, PackageDiff{
				Package:    name + "@" + newVer,
				ChangeType: "escalated",
				OldCaps:    oldCaps,
				NewCaps:    newCaps,
				RiskDelta:  delta,
			})
		}
	}

	r.Score = computeScore(r)
	return r, nil
}

// detectNodeLockfile returns the lockfile name and a file-path reader for the current dir.
func detectNodeLockfile(dir string) (string, func(string) (map[string]string, error), error) {
	readers := map[string]func(string) (map[string]string, error){
		"package-lock.json": readNodePackages,
		"yarn.lock":         readYarnPackages,
		"pnpm-lock.yaml":    readPnpmPackages,
	}
	for _, lf := range []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml"} {
		if _, err := os.Stat(filepath.Join(dir, lf)); err == nil {
			return lf, readers[lf], nil
		}
	}
	return "", nil, fmt.Errorf("no supported Node lockfile found in %s", dir)
}

func readPnpmPackages(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return readPnpmPackagesFromBytes(data)
}

func readYarnPackages(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return readYarnPackagesFromBytes(data)
}

// nodePackagesFromBytes parses a lockfile given its filename and raw bytes.
func nodePackagesFromBytes(lockfile string, data []byte) (map[string]string, error) {
	switch lockfile {
	case "pnpm-lock.yaml":
		return readPnpmPackagesFromBytes(data)
	case "yarn.lock":
		return readYarnPackagesFromBytes(data)
	default:
		return readNodePackagesFromBytes(data)
	}
}

// readPnpmPackagesFromBytes parses pnpm-lock.yaml for package name→version.
// Handles v6 (/name@ver:) and v9 (name@ver:) snapshot formats.
func readPnpmPackagesFromBytes(data []byte) (map[string]string, error) {
	pkgs := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		// Package entry: "  /name@ver:" or "  name@ver:" (two leading spaces, ends with colon)
		if !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   ") {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if !strings.HasSuffix(trimmed, ":") {
			continue
		}
		entry := strings.TrimSuffix(trimmed, ":")
		entry = strings.TrimPrefix(entry, "/") // v6 has leading slash
		// entry is now "name@version" or "@scope/name@version"
		if idx := strings.LastIndex(entry, "@"); idx > 0 {
			name := entry[:idx]
			ver := entry[idx+1:]
			// Strip peer deps suffix: "name@1.0.0(peer@2.0.0)" → "1.0.0"
			if pIdx := strings.Index(ver, "("); pIdx >= 0 {
				ver = ver[:pIdx]
			}
			if name != "" && ver != "" {
				pkgs[name] = ver
			}
		}
	}
	return pkgs, nil
}

// readYarnPackagesFromBytes parses yarn.lock for package name→version.
func readYarnPackagesFromBytes(data []byte) (map[string]string, error) {
	pkgs := make(map[string]string)
	var currentName string

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		// Package declaration (no leading whitespace).
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			decl := strings.TrimSuffix(strings.TrimSpace(line), ":")
			first := strings.Split(decl, ",")[0]
			first = strings.TrimSpace(strings.Trim(first, `"`))
			if idx := strings.LastIndex(first, "@"); idx > 0 {
				currentName = first[:idx]
			}
			continue
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "version ") && currentName != "" {
			ver := strings.Trim(strings.TrimPrefix(trimmed, "version "), `"`)
			pkgs[currentName] = ver
		}
	}
	return pkgs, nil
}

func readNodePackages(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return readNodePackagesFromBytes(data)
}

func readNodePackagesFromBytes(data []byte) (map[string]string, error) {
	var raw struct {
		Packages map[string]struct {
			Version string `json:"version"`
			Link    bool   `json:"link"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	pkgs := make(map[string]string)
	if len(raw.Packages) > 0 {
		for key, p := range raw.Packages {
			if key == "" || p.Link {
				continue
			}
			name := strings.TrimPrefix(key, "node_modules/")
			if idx := strings.LastIndex(name, "node_modules/"); idx >= 0 {
				name = name[idx+len("node_modules/"):]
			}
			pkgs[name] = p.Version
		}
	} else {
		for name, d := range raw.Dependencies {
			pkgs[name] = d.Version
		}
	}
	return pkgs, nil
}

// inferNodeCaps returns a rough capability list for a Node package name.
func inferNodeCaps(name string) []string {
	lower := strings.ToLower(name)
	var caps []string
	if strings.Contains(lower, "exec") || strings.Contains(lower, "spawn") || strings.Contains(lower, "shell") {
		caps = append(caps, "exec")
	}
	if strings.Contains(lower, "net") || strings.Contains(lower, "http") || strings.Contains(lower, "request") || strings.Contains(lower, "axios") || strings.Contains(lower, "fetch") {
		caps = append(caps, "network")
	}
	if strings.Contains(lower, "crypto") || strings.Contains(lower, "hash") {
		caps = append(caps, "crypto")
	}
	if strings.Contains(lower, "fs") || strings.Contains(lower, "file") || strings.Contains(lower, "path") {
		caps = append(caps, "fs:read")
	}
	return caps
}

// ---------------------------------------------------------------------------
// Git helper
// ---------------------------------------------------------------------------

// readBase reads a file from a git ref or from a direct file path.
// It first tries to interpret base as a file path; if not found, treats it as a git ref.
func readBase(dir, base, file string) ([]byte, error) {
	// Check if base is a direct file path.
	if data, err := os.ReadFile(base); err == nil {
		return data, nil
	}
	// Treat as git ref.
	return readGitRef(dir, base, file)
}

func readGitRef(dir, ref, file string) ([]byte, error) {
	out, err := exec.Command("git", "-C", dir, "show", ref+":"+file).Output()
	if err != nil {
		return nil, fmt.Errorf("git show %s:%s: %w", ref, file, err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

func capsToLevel(caps []string) string {
	for _, c := range caps {
		if c == "exec" || c == "unsafe" || c == "plugin" {
			return "HIGH"
		}
	}
	for _, c := range caps {
		if c == "network" || c == "fs:write" {
			return "MEDIUM"
		}
	}
	if len(caps) > 0 {
		return "MEDIUM"
	}
	return "LOW"
}

func riskVal(level string) int {
	switch level {
	case "HIGH":
		return 2
	case "MEDIUM":
		return 1
	default:
		return 0
	}
}

func levelDelta(newLevel, _ string) float64 {
	switch newLevel {
	case "HIGH":
		return 15
	case "MEDIUM":
		return 8
	default:
		return 0
	}
}

func computeScore(r DiffReport) float64 {
	total := 0.0
	for _, pd := range r.NewPackages {
		total += pd.RiskDelta
	}
	for _, pd := range r.Escalations {
		total += pd.RiskDelta
	}
	if total > 20 {
		total = 20
	}
	return total
}
