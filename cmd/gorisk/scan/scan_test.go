package scan

import (
	"testing"
	"time"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/taint"
)

func TestBuildExceptions(t *testing.T) {
	allowExceptions := []PolicyException{
		{
			Package:       "test/pkg1",
			Capabilities:  []string{"exec", "network"},
			Justification: "test justification",
		},
		{
			Package:       "test/pkg2",
			Taint:         []string{"network→exec", "env→exec"},
			Justification: "taint test",
		},
	}

	exceptions, taintExceptions, stats := buildExceptions(allowExceptions)

	// Check capability exceptions
	if len(exceptions) != 1 {
		t.Errorf("expected 1 capability exception, got %d", len(exceptions))
	}
	if !exceptions["test/pkg1"]["exec"] {
		t.Error("expected exec capability exception for test/pkg1")
	}
	if !exceptions["test/pkg1"]["network"] {
		t.Error("expected network capability exception for test/pkg1")
	}

	// Check taint exceptions
	if len(taintExceptions) != 1 {
		t.Errorf("expected 1 taint exception package, got %d", len(taintExceptions))
	}
	if !taintExceptions["test/pkg2"]["network→exec"] {
		t.Error("expected network→exec taint exception for test/pkg2")
	}

	// Check stats
	if stats.Applied != 2 {
		t.Errorf("expected 2 applied exceptions, got %d", stats.Applied)
	}
	if stats.TaintSuppressed != 2 {
		t.Errorf("expected 2 taint suppressions, got %d", stats.TaintSuppressed)
	}
}

func TestBuildExceptionsExpired(t *testing.T) {
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")

	allowExceptions := []PolicyException{
		{
			Package:       "test/pkg",
			Capabilities:  []string{"exec"},
			Expires:       yesterday,
			Justification: "expired exception",
		},
	}

	exceptions, _, stats := buildExceptions(allowExceptions)

	// Expired exceptions should not be applied
	if len(exceptions) != 0 {
		t.Errorf("expected 0 applied exceptions for expired policy, got %d", len(exceptions))
	}

	if stats.Expired != 1 {
		t.Errorf("expected 1 expired exception, got %d", stats.Expired)
	}
}

func TestBuildExceptionsMissingJustification(t *testing.T) {
	allowExceptions := []PolicyException{
		{
			Package:      "test/pkg",
			Capabilities: []string{"exec"},
			// No justification or ticket
		},
	}

	_, _, stats := buildExceptions(allowExceptions)

	// Exception should still be applied even without justification
	if stats.Applied != 1 {
		t.Errorf("expected exception to be applied even without justification, got %d applied", stats.Applied)
	}
}

func TestBuildExceptionsValidExpiry(t *testing.T) {
	tomorrow := time.Now().AddDate(0, 0, 1).Format("2006-01-02")

	allowExceptions := []PolicyException{
		{
			Package:       "test/pkg",
			Capabilities:  []string{"exec"},
			Expires:       tomorrow,
			Justification: "valid exception",
		},
	}

	exceptions, _, stats := buildExceptions(allowExceptions)

	// Non-expired exceptions should be applied
	if len(exceptions) != 1 {
		t.Errorf("expected 1 applied exception, got %d", len(exceptions))
	}

	if stats.Expired != 0 {
		t.Errorf("expected 0 expired exceptions, got %d", stats.Expired)
	}
}

func TestFilterTaintFindings(t *testing.T) {
	findings := []taint.TaintFinding{
		{
			Package: "test/pkg1",
			Source:  capability.CapNetwork,
			Sink:    capability.CapExec,
			Risk:    "HIGH",
		},
		{
			Package: "test/pkg1",
			Source:  capability.CapEnv,
			Sink:    capability.CapExec,
			Risk:    "HIGH",
		},
		{
			Package: "test/pkg2",
			Source:  capability.CapNetwork,
			Sink:    capability.CapExec,
			Risk:    "HIGH",
		},
	}

	// Suppress network→exec for test/pkg1
	taintExceptions := map[string]map[string]bool{
		"test/pkg1": {
			"network→exec": true,
		},
	}

	filtered := filterTaintFindings(findings, taintExceptions)

	// Should filter out the first finding (test/pkg1 network→exec)
	if len(filtered) != 2 {
		t.Errorf("expected 2 findings after filtering, got %d", len(filtered))
	}

	// Verify the correct finding was filtered
	for _, f := range filtered {
		if f.Package == "test/pkg1" && f.Source == capability.CapNetwork && f.Sink == capability.CapExec {
			t.Error("expected network→exec for test/pkg1 to be filtered")
		}
	}

	// Verify env→exec for test/pkg1 is still present
	foundEnvExec := false
	for _, f := range filtered {
		if f.Package == "test/pkg1" && f.Source == capability.CapEnv && f.Sink == capability.CapExec {
			foundEnvExec = true
		}
	}
	if !foundEnvExec {
		t.Error("expected env→exec for test/pkg1 to remain")
	}
}

func TestFilterTaintFindingsNoExceptions(t *testing.T) {
	findings := []taint.TaintFinding{
		{
			Package: "test/pkg",
			Source:  capability.CapNetwork,
			Sink:    capability.CapExec,
			Risk:    "HIGH",
		},
	}

	filtered := filterTaintFindings(findings, nil)

	// No exceptions, all findings should remain
	if len(filtered) != len(findings) {
		t.Errorf("expected %d findings, got %d", len(findings), len(filtered))
	}
}
