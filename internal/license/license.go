package license

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

type LicenseReport struct {
	Module  string
	Version string
	License string
	Risky   bool
	Reason  string
}

var riskyLicenses = map[string]string{
	"GPL-2.0":  "copyleft license: GPL-2.0",
	"GPL-3.0":  "copyleft license: GPL-3.0",
	"AGPL-3.0": "copyleft license: AGPL-3.0",
	"LGPL-2.1": "copyleft license: LGPL-2.1",
	"LGPL-3.0": "copyleft license: LGPL-3.0",
	"EUPL-1.1": "copyleft license: EUPL-1.1",
	"EUPL-1.2": "copyleft license: EUPL-1.2",
	"CCDL-1.0": "copyleft license: CDDL-1.0",
}

func githubToken() string {
	return os.Getenv("GORISK_GITHUB_TOKEN")
}

func githubOwnerRepo(modulePath string) (string, string, bool) {
	parts := strings.SplitN(modulePath, "/", 4)
	if len(parts) < 3 || parts[0] != "github.com" {
		return "", "", false
	}
	return parts[1], parts[2], true
}

func Detect(modulePath, version string) LicenseReport {
	r := LicenseReport{
		Module:  modulePath,
		Version: version,
		License: "unknown",
		Risky:   true,
		Reason:  "license not detected",
	}

	owner, repo, isGH := githubOwnerRepo(modulePath)
	if !isGH {
		return r
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/license", owner, repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return r
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if tok := githubToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return r
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return r
	}

	var result struct {
		License struct {
			SPDXID string `json:"spdx_id"`
		} `json:"license"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return r
	}

	spdx := result.License.SPDXID
	if spdx == "" || spdx == "NOASSERTION" {
		return r
	}

	r.License = spdx
	if reason, isRisky := riskyLicenses[spdx]; isRisky {
		r.Risky = true
		r.Reason = reason
	} else {
		r.Risky = false
		r.Reason = ""
	}
	return r
}
