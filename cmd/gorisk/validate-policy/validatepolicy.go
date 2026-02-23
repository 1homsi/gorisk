package validatepolicy

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

// Run is the entry point for `gorisk validate-policy`.
func Run(args []string) int {
	fs := flag.NewFlagSet("validate-policy", flag.ExitOnError)
	policyFile := fs.String("policy", ".gorisk-policy.json", "policy file to validate")
	fs.Parse(args)

	if fs.NArg() > 0 {
		*policyFile = fs.Arg(0)
	}

	data, err := os.ReadFile(*policyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot read %s: %v\n", *policyFile, err)
		return 2
	}

	// Validate by decoding into a map to catch unknown fields.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid JSON in %s: %v\n", *policyFile, err)
		return 1
	}

	known := map[string]bool{
		"version": true, "fail_on": true, "max_health_score": true,
		"min_health_score": true, "block_archived": true,
		"deny_capabilities": true, "allow_exceptions": true,
		"max_dep_depth": true, "exclude_packages": true,
		"confidence_threshold": true, "suppress": true,
	}

	var errs []string
	for field := range raw {
		if !known[field] {
			suggestion := closestField(field, known)
			if suggestion != "" {
				errs = append(errs, fmt.Sprintf("  unknown field %q — did you mean %q?", field, suggestion))
			} else {
				errs = append(errs, fmt.Sprintf("  unknown field %q", field))
			}
		}
	}

	// Validate fail_on value.
	if v, ok := raw["fail_on"]; ok {
		var failOn string
		if json.Unmarshal(v, &failOn) == nil {
			switch failOn {
			case "low", "medium", "high":
			default:
				errs = append(errs, fmt.Sprintf("  fail_on: %q is invalid (must be low|medium|high)", failOn))
			}
		}
	}

	if len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "policy validation failed (%s):\n", *policyFile)
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, e)
		}
		return 1
	}

	fmt.Fprintf(os.Stdout, "✓ %s is valid\n", *policyFile)
	return 0
}

// closestField returns the most similar known field name using simple edit distance.
func closestField(s string, known map[string]bool) string {
	best := ""
	bestDist := 4 // max levenshtein distance to suggest
	for k := range known {
		d := levenshtein(s, k)
		if d < bestDist {
			bestDist = d
			best = k
		}
	}
	return best
}

func levenshtein(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}
	dp := make([][]int, len(a)+1)
	for i := range dp {
		dp[i] = make([]int, len(b)+1)
		dp[i][0] = i
	}
	for j := range dp[0] {
		dp[0][j] = j
	}
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			if a[i-1] == b[j-1] {
				dp[i][j] = dp[i-1][j-1]
			} else {
				dp[i][j] = 1 + min(dp[i-1][j], min(dp[i][j-1], dp[i-1][j-1]))
			}
		}
	}
	return dp[len(a)][len(b)]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
