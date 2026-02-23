package clojure

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
)

// clojurePatterns holds the Clojure PatternSet loaded from languages/clojure.yaml.
var clojurePatterns = capability.MustLoadPatterns("clojure")

// Detect walks .clj, .cljs, and .cljc files in dir and returns the combined
// capability set found in those source files.
func Detect(dir string) capability.CapabilitySet {
	var caps capability.CapabilitySet

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".clj", ".cljs", ".cljc":
			scanCljFile(path, &caps)
		}
		return nil
	})

	return caps
}

// scanCljFile scans a single Clojure source file for capability evidence.
func scanCljFile(path string, caps *capability.CapabilitySet) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	lineNo := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineNo++
		trimmed := strings.TrimSpace(line)

		// Detect require/ns require forms:
		//   (require '[X.Y.Z ...])
		//   (:require [X.Y.Z ...])
		if strings.Contains(trimmed, "require") {
			checkCljRequire(line, caps, path, lineNo)
		}

		// Match call-site patterns (substring match).
		for pattern, patCaps := range clojurePatterns.CallSites {
			if strings.Contains(line, pattern) {
				for _, c := range patCaps {
					caps.AddWithEvidence(c, capability.CapabilityEvidence{
						File:       path,
						Line:       lineNo,
						Context:    trimmed,
						Via:        "callSite",
						Confidence: 0.75,
					})
				}
			}
		}
	}
}

// checkCljRequire detects capabilities from Clojure require/ns forms.
// Handles:
//
//	(require '[clojure.java.shell :as shell])
//	(:require [clj-http.client :as http])
//	(require 'clojure.java.io)
func checkCljRequire(line string, caps *capability.CapabilitySet, path string, lineNo int) {
	trimmed := strings.TrimSpace(line)

	// Locate the require keyword and work on the remainder.
	idx := strings.Index(trimmed, "require")
	if idx < 0 {
		return
	}
	rest := trimmed[idx+len("require"):]

	// Extract namespace tokens from the rest of the line.
	// Strip EDN punctuation and split.
	rest = strings.NewReplacer(
		"[", " ", "]", " ",
		"(", " ", ")", " ",
		"'", " ", "`", " ",
		",", " ",
	).Replace(rest)

	fields := strings.Fields(rest)
	for _, field := range fields {
		// Skip keywords like :as, :refer, :all, :only.
		if strings.HasPrefix(field, ":") {
			continue
		}
		// Skip the vector contents that follow :as / :refer.
		if field == "all" || field == "only" {
			continue
		}

		// Convert Clojure namespace notation to canonical key form.
		// clojure.java.shell → clojure.java.shell (match as-is first)
		// clj-http.client   → clj-http (package portion)
		candidates := nsVariants(field)
		for _, candidate := range candidates {
			if importCaps, ok := clojurePatterns.Imports[candidate]; ok {
				for _, c := range importCaps {
					caps.AddWithEvidence(c, capability.CapabilityEvidence{
						File:       path,
						Line:       lineNo,
						Context:    strings.TrimSpace(line),
						Via:        "import",
						Confidence: 0.90,
					})
				}
				break
			}
		}
	}
}

// nsVariants generates candidate lookup keys from a Clojure namespace string.
// For example "clj-http.client" → ["clj-http.client", "clj-http", "clj-http/client"].
func nsVariants(ns string) []string {
	ns = strings.Trim(ns, `"'[]()`)
	if ns == "" {
		return nil
	}

	candidates := []string{ns}

	// If the ns contains a dot, try the first segment (top-level library).
	if dot := strings.IndexByte(ns, '.'); dot > 0 {
		candidates = append(candidates, ns[:dot])
	}

	// Replace dots with slashes for Maven-style artifact IDs.
	withSlash := strings.ReplaceAll(ns, ".", "/")
	if withSlash != ns {
		candidates = append(candidates, withSlash)
	}

	return candidates
}
