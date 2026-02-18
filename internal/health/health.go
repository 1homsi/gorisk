package health

import (
	"time"

	"github.com/1homsi/gorisk/internal/report"
)

func Score(modulePath, version string) report.HealthReport {
	hr := report.HealthReport{
		Module:  modulePath,
		Version: version,
		Score:   100,
		Signals: make(map[string]int),
	}

	owner, repo, isGH := githubOwnerRepo(modulePath)
	if isGH {
		ghRepo, err := fetchGHRepo(owner, repo)
		if err == nil {
			if ghRepo.Archived {
				hr.Archived = true
				hr.Score -= 50
				hr.Signals["archived"] = -50
			}

			age := time.Since(ghRepo.PushedAt)
			ageDays := int(age.Hours() / 24)
			var agePenalty int
			switch {
			case ageDays > 730:
				agePenalty = -30
			case ageDays > 365:
				agePenalty = -15
			case ageDays > 180:
				agePenalty = -5
			default:
				agePenalty = 0
			}
			hr.Score += agePenalty
			hr.Signals["commit_age"] = agePenalty

			releases, err := fetchGHReleases(owner, repo)
			if err == nil {
				var releaseBonus int
				switch {
				case len(releases) >= 5:
					releaseBonus = 15
				case len(releases) >= 2:
					releaseBonus = 8
				case len(releases) == 1:
					releaseBonus = 3
				}
				hr.Score += releaseBonus
				hr.Signals["release_frequency"] = releaseBonus
			}
		}
	}

	cveIDs, err := fetchOSVVulns(modulePath)
	if err == nil {
		hr.CVECount = len(cveIDs)
		hr.CVEs = cveIDs
		penalty := -30 * len(cveIDs)
		hr.Score += penalty
		hr.Signals["cve_count"] = penalty
	}

	if hr.Score < 0 {
		hr.Score = 0
	}
	if hr.Score > 100 {
		hr.Score = 100
	}

	return hr
}
