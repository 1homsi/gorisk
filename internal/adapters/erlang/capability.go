package erlang

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
)

// erlangPatterns holds the Erlang PatternSet loaded from languages/erlang.yaml.
var erlangPatterns = capability.MustLoadPatterns("erlang")

// Detect walks .erl and .hrl files in dir and returns the combined capability
// set found in those source files.
func Detect(dir string) capability.CapabilitySet {
	var caps capability.CapabilitySet

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".erl", ".hrl":
			scanErlFile(path, &caps)
		}
		return nil
	})

	return caps
}

// scanErlFile scans a single Erlang source file for capability evidence.
func scanErlFile(path string, caps *capability.CapabilitySet) {
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

		// Detect module attributes that reference libraries:
		//   -include_lib("X/include/Y.hrl").
		//   -behaviour(X).
		//   -use(X).
		//   -import(X, [...]).
		if strings.HasPrefix(trimmed, "-include_lib(") ||
			strings.HasPrefix(trimmed, "-behaviour(") ||
			strings.HasPrefix(trimmed, "-behavior(") ||
			strings.HasPrefix(trimmed, "-use(") ||
			strings.HasPrefix(trimmed, "-import(") {
			checkErlImport(line, caps, path, lineNo)
		}

		// Match call-site patterns (substring match).
		for pattern, patCaps := range erlangPatterns.CallSites {
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

// checkErlImport detects capabilities from Erlang module attribute declarations.
func checkErlImport(line string, caps *capability.CapabilitySet, path string, lineNo int) {
	trimmed := strings.TrimSpace(line)

	var appName string

	switch {
	case strings.HasPrefix(trimmed, "-include_lib("):
		// -include_lib("cowboy/include/cowboy.hrl").
		// Extract the application name (first path component inside quotes).
		rest := trimmed[len("-include_lib("):]
		rest = strings.Trim(rest, `"' `)
		// The app name is the part before the first "/".
		if slash := strings.IndexByte(rest, '/'); slash > 0 {
			appName = rest[:slash]
		} else {
			appName = strings.TrimRight(rest, ").")
		}

	case strings.HasPrefix(trimmed, "-behaviour("), strings.HasPrefix(trimmed, "-behavior("):
		// -behaviour(gen_server).
		rest := trimmed
		if after, ok := strings.CutPrefix(rest, "-behaviour("); ok {
			rest = after
		} else if after, ok := strings.CutPrefix(rest, "-behavior("); ok {
			rest = after
		}
		appName = strings.Trim(rest, ").\t ")

	case strings.HasPrefix(trimmed, "-use("):
		rest := trimmed[len("-use("):]
		appName = strings.Trim(rest, ").\t ")

	case strings.HasPrefix(trimmed, "-import("):
		// -import(lists, [map/2, filter/2]).
		rest := trimmed[len("-import("):]
		if comma := strings.IndexByte(rest, ','); comma > 0 {
			appName = strings.TrimSpace(rest[:comma])
		} else {
			appName = strings.Trim(rest, ").\t ")
		}
	}

	appName = strings.TrimSpace(appName)
	if appName == "" {
		return
	}

	if importCaps, ok := erlangPatterns.Imports[appName]; ok {
		for _, c := range importCaps {
			caps.AddWithEvidence(c, capability.CapabilityEvidence{
				File:       path,
				Line:       lineNo,
				Context:    strings.TrimSpace(line),
				Via:        "import",
				Confidence: 0.90,
			})
		}
	}
}
