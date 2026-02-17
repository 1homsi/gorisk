package report

import (
	"encoding/json"
	"io"
)

func WriteCapabilitiesJSON(w io.Writer, reports []CapabilityReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(reports)
}

func WriteHealthJSON(w io.Writer, reports []HealthReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(reports)
}

func WriteUpgradeJSON(w io.Writer, r UpgradeReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func WriteImpactJSON(w io.Writer, r ImpactReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func WriteScanJSON(w io.Writer, r ScanReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
