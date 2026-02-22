// Package topology computes lockfile-structure risk signals.
package topology

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/1homsi/gorisk/internal/adapters/node"
)

// Signal is a single named risk signal with its contribution.
type Signal struct {
	Name  string
	Value int
	Score float64
}

// TopologyReport holds all lockfile-structure metrics and the resulting score.
type TopologyReport struct {
	DirectDeps        int
	TotalDeps         int
	MaxDepth          int
	DeepPackagePct    float64 // % of pkgs at depth >= 4
	MajorVersionSkew  int     // modules with /v2+ path (Go) or major != 1 (Node)
	DuplicateVersions int     // packages present at > 1 version
	LockfileChurn     int     // commits touching lockfile in last 90 days (-1 = no git)
	Signals           []Signal
	Score             float64 // 0-20
}

// Compute runs the topology engine for the given directory and language.
// lang must be one of "auto", "go", or "node".
func Compute(dir, lang string) (TopologyReport, error) {
	resolved, err := resolveLang(dir, lang)
	if err != nil {
		return TopologyReport{}, err
	}
	switch resolved {
	case "go":
		return computeGo(dir)
	case "node":
		return computeNode(dir)
	default:
		return TopologyReport{}, fmt.Errorf("unsupported language: %s", resolved)
	}
}

// resolveLang returns the concrete language ("go" or "node") from the lang hint.
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
	return "", fmt.Errorf("could not detect language in %s (no go.mod or lockfile found)", dir)
}

// ---------------------------------------------------------------------------
// Go implementation
// ---------------------------------------------------------------------------

func computeGo(dir string) (TopologyReport, error) {
	r := TopologyReport{LockfileChurn: -1}

	// Parse go.mod for direct deps and major-version skew.
	direct, skew, err := parseGoMod(dir)
	if err != nil {
		return r, fmt.Errorf("parse go.mod: %w", err)
	}
	r.DirectDeps = len(direct)
	r.MajorVersionSkew = skew

	// Run `go mod graph` for total deps and depth via BFS.
	total, maxDepth, deepPct, dups, err := goModGraph(dir)
	if err == nil {
		r.TotalDeps = total
		r.MaxDepth = maxDepth
		r.DeepPackagePct = deepPct
		r.DuplicateVersions = dups
	}

	// Lockfile churn via git.
	r.LockfileChurn = gitChurn(dir, "go.mod", "go.sum")

	r.Signals, r.Score = computeScore(r)
	return r, nil
}

// parseGoMod returns (set of direct requires, major-version-skew count, error).
func parseGoMod(dir string) (map[string]bool, int, error) {
	data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return nil, 0, err
	}

	direct := make(map[string]bool)
	skew := 0
	inRequire := false

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Block: require (
		if line == "require (" {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}

		// Single-line: require foo/bar v1.2.3
		if strings.HasPrefix(line, "require ") {
			rest := strings.TrimPrefix(line, "require ")
			parts := strings.Fields(rest)
			if len(parts) >= 1 {
				mod := parts[0]
				direct[mod] = true
				if hasMajorVersion(mod) {
					skew++
				}
			}
			continue
		}

		if inRequire && line != "" && !strings.HasPrefix(line, "//") {
			parts := strings.Fields(line)
			if len(parts) >= 1 {
				mod := parts[0]
				// indirect check
				isIndirect := false
				for i, p := range parts {
					if p == "//" && i+1 < len(parts) && parts[i+1] == "indirect" {
						isIndirect = true
						break
					}
				}
				if !isIndirect {
					direct[mod] = true
				}
				if hasMajorVersion(mod) {
					skew++
				}
			}
		}
	}
	return direct, skew, nil
}

func hasMajorVersion(mod string) bool {
	parts := strings.Split(mod, "/")
	if len(parts) == 0 {
		return false
	}
	last := parts[len(parts)-1]
	if len(last) < 2 || last[0] != 'v' {
		return false
	}
	for _, c := range last[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// goModGraph runs `go mod graph` and computes depth/duplicates via BFS.
func goModGraph(dir string) (total, maxDepth int, deepPct float64, dups int, err error) {
	cmd := exec.Command("go", "mod", "graph")
	cmd.Dir = dir
	out, runErr := cmd.Output()
	if runErr != nil {
		err = fmt.Errorf("go mod graph: %w", runErr)
		return
	}

	// Build adjacency list.
	adj := make(map[string][]string)
	deps := make(map[string]bool)
	// track versions per base module path
	versions := make(map[string]map[string]bool)

	scanner := bufio.NewScanner(bytes.NewReader(out))
	var root string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		from, to := parts[0], parts[1]
		if root == "" {
			root = from
		}
		adj[from] = append(adj[from], to)
		deps[to] = true

		// Track duplicate versions.
		baseTo := moduleBase(to)
		if versions[baseTo] == nil {
			versions[baseTo] = make(map[string]bool)
		}
		versions[baseTo][to] = true
	}

	// Count duplicates (same base path, multiple versions).
	for _, vs := range versions {
		if len(vs) > 1 {
			dups++
		}
	}

	total = len(deps)
	if total == 0 || root == "" {
		return
	}

	// BFS from root to compute depth of each node.
	depthMap := make(map[string]int)
	queue := []string{root}
	depthMap[root] = 0
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		d := depthMap[cur]
		if d > maxDepth {
			maxDepth = d
		}
		for _, next := range adj[cur] {
			if _, seen := depthMap[next]; !seen {
				depthMap[next] = d + 1
				queue = append(queue, next)
			}
		}
	}

	// DeepPackagePct: % of non-root packages at depth >= 4.
	deep := 0
	depCount := 0
	for node, d := range depthMap {
		if node == root {
			continue
		}
		depCount++
		if d >= 4 {
			deep++
		}
	}
	if depCount > 0 {
		deepPct = float64(deep) / float64(depCount) * 100
	}
	return
}

// moduleBase strips the version component: "github.com/foo/bar@v2.0.0" → "github.com/foo/bar".
func moduleBase(mod string) string {
	if idx := strings.Index(mod, "@"); idx >= 0 {
		mod = mod[:idx]
	}
	parts := strings.Split(mod, "/")
	if len(parts) > 0 && hasMajorVersion(parts[len(parts)-1]) {
		return strings.Join(parts[:len(parts)-1], "/")
	}
	return mod
}

// ---------------------------------------------------------------------------
// Node implementation
// ---------------------------------------------------------------------------

func computeNode(dir string) (TopologyReport, error) {
	r := TopologyReport{LockfileChurn: -1}

	pkgs, err := loadNodePackages(dir)
	if err != nil {
		return r, err
	}

	direct := 0
	total := len(pkgs)
	// Track name → set of versions.
	versions := make(map[string]map[string]bool)
	// Build adjacency for depth calculation.
	adj := make(map[string][]string)
	var rootDeps []string

	for _, p := range pkgs {
		if p.Direct {
			direct++
			rootDeps = append(rootDeps, p.Name+"@"+p.Version)
		}
		key := p.Name + "@" + p.Version
		if versions[p.Name] == nil {
			versions[p.Name] = make(map[string]bool)
		}
		versions[p.Name][p.Version] = true
		adj[key] = append(adj[key], p.Dependencies...)
	}

	r.DirectDeps = direct
	r.TotalDeps = total

	// Duplicates.
	for _, vs := range versions {
		if len(vs) > 1 {
			r.DuplicateVersions++
		}
	}

	// Depth BFS from virtual root.
	if len(rootDeps) > 0 {
		depthMap := make(map[string]int)
		queue := make([]string, len(rootDeps))
		copy(queue, rootDeps)
		for _, rd := range rootDeps {
			depthMap[rd] = 1
		}
		deep := 0
		counted := 0
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			d := depthMap[cur]
			if d > r.MaxDepth {
				r.MaxDepth = d
			}
			counted++
			if d >= 4 {
				deep++
			}
			for _, next := range adj[cur] {
				if vs, ok := versions[next]; ok {
					for v := range vs {
						nk := next + "@" + v
						if _, seen := depthMap[nk]; !seen {
							depthMap[nk] = d + 1
							queue = append(queue, nk)
						}
					}
				}
			}
		}
		if counted > 0 {
			r.DeepPackagePct = float64(deep) / float64(counted) * 100
		}
	}

	// Lockfile churn.
	for _, lf := range []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml"} {
		if _, err := os.Stat(filepath.Join(dir, lf)); err == nil {
			r.LockfileChurn = gitChurn(dir, lf)
			break
		}
	}

	r.Signals, r.Score = computeScore(r)
	return r, nil
}

// nodePackage is a minimal struct for the topology engine.
type nodePackage struct {
	Name         string
	Version      string
	Direct       bool
	Dependencies []string
}

// loadNodePackages delegates to the existing node adapter which handles
// package-lock.json (v1/v2/v3), yarn.lock, and pnpm-lock.yaml.
func loadNodePackages(dir string) ([]nodePackage, error) {
	pkgs, err := node.Load(dir)
	if err != nil {
		return nil, err
	}
	result := make([]nodePackage, len(pkgs))
	for i, p := range pkgs {
		result[i] = nodePackage{
			Name:         p.Name,
			Version:      p.Version,
			Direct:       p.Direct,
			Dependencies: p.Dependencies,
		}
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Git churn helper
// ---------------------------------------------------------------------------

// gitChurn returns the number of commits touching any of the given files in
// the last 90 days. Returns -1 if git is not available or the directory is
// not a git repo.
func gitChurn(dir string, files ...string) int {
	since := time.Now().AddDate(0, 0, -90).Format("2006-01-02")
	args := []string{"-C", dir, "log", "--oneline", "--since=" + since, "--"}
	args = append(args, files...)
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return -1
	}
	count := 0
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	return count
}

// ---------------------------------------------------------------------------
// Score computation
// ---------------------------------------------------------------------------

func computeScore(r TopologyReport) ([]Signal, float64) {
	var signals []Signal
	var total float64

	// DirectDeps signal.
	var ddScore float64
	switch {
	case r.DirectDeps > 100:
		ddScore = 8
	case r.DirectDeps >= 50:
		ddScore = 5
	case r.DirectDeps >= 20:
		ddScore = 2
	default:
		ddScore = 0
	}
	signals = append(signals, Signal{Name: "DirectDeps", Value: r.DirectDeps, Score: ddScore})
	total += ddScore

	// DeepPackagePct signal.
	var dpScore float64
	switch {
	case r.DeepPackagePct > 60:
		dpScore = 5
	case r.DeepPackagePct >= 30:
		dpScore = 2
	default:
		dpScore = 0
	}
	signals = append(signals, Signal{Name: "DeepPackagePct", Value: int(r.DeepPackagePct), Score: dpScore})
	total += dpScore

	// MajorVersionSkew signal.
	var mvScore float64
	switch {
	case r.MajorVersionSkew > 8:
		mvScore = 3
	case r.MajorVersionSkew >= 3:
		mvScore = 2
	default:
		mvScore = 0
	}
	signals = append(signals, Signal{Name: "MajorVersionSkew", Value: r.MajorVersionSkew, Score: mvScore})
	total += mvScore

	// DuplicateVersions signal.
	var dvScore float64
	switch {
	case r.DuplicateVersions > 10:
		dvScore = 3
	case r.DuplicateVersions >= 3:
		dvScore = 2
	default:
		dvScore = 0
	}
	signals = append(signals, Signal{Name: "DuplicateVersions", Value: r.DuplicateVersions, Score: dvScore})
	total += dvScore

	// LockfileChurn signal.
	var lcScore float64
	if r.LockfileChurn > 10 {
		lcScore = 4
	} else if r.LockfileChurn >= 3 {
		lcScore = 2
	}
	signals = append(signals, Signal{Name: "LockfileChurn", Value: r.LockfileChurn, Score: lcScore})
	total += lcScore

	// Cap at 20.
	if total > 20 {
		total = 20
	}
	return signals, total
}
