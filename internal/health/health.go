package health

import (
	"sync"
	"time"

	"github.com/1homsi/gorisk/internal/report"
)

type ModuleRef struct {
	Path    string
	Version string
}

// HealthTiming holds aggregate timing information from a ScoreAll run.
type HealthTiming struct {
	Total       time.Duration
	GithubCalls int
	OsvCalls    int
	GithubTime  time.Duration
	OsvTime     time.Duration
	Workers     int
	ModuleCount int
}

// ScoreAll scores all modules in parallel and returns health reports with timing data.
func ScoreAll(mods []ModuleRef) ([]report.HealthReport, HealthTiming) {
	if len(mods) == 0 {
		return nil, HealthTiming{}
	}

	type result struct {
		idx    int
		hr     report.HealthReport
		timing HealthTiming
	}

	results := make([]report.HealthReport, len(mods))
	jobs := make(chan int, len(mods))
	resChan := make(chan result, len(mods))

	for i := range mods {
		jobs <- i
	}
	close(jobs)

	workers := 10
	if len(mods) < workers {
		workers = len(mods)
	}

	t0 := time.Now()

	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for i := range jobs {
				hr, t := scoreWithTiming(mods[i].Path, mods[i].Version)
				resChan <- result{idx: i, hr: hr, timing: t}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resChan)
	}()

	var total HealthTiming
	for r := range resChan {
		results[r.idx] = r.hr
		total.GithubCalls += r.timing.GithubCalls
		total.OsvCalls += r.timing.OsvCalls
		total.GithubTime += r.timing.GithubTime
		total.OsvTime += r.timing.OsvTime
	}
	total.Total = time.Since(t0)
	total.Workers = workers
	total.ModuleCount = len(mods)

	return results, total
}

// scoreWithTiming scores a single module and records per-API timing.
func scoreWithTiming(modulePath, version string) (report.HealthReport, HealthTiming) {
	var t HealthTiming
	hr := report.HealthReport{
		Module:  modulePath,
		Version: version,
		Score:   100,
		Signals: make(map[string]int),
	}

	owner, repo, isGH := githubOwnerRepo(modulePath)
	if isGH {
		t0 := time.Now()
		ghRepo, err := fetchGHRepo(owner, repo)
		t.GithubTime += time.Since(t0)
		t.GithubCalls++

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

			t1 := time.Now()
			releases, err := fetchGHReleases(owner, repo)
			t.GithubTime += time.Since(t1)
			t.GithubCalls++

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

	t2 := time.Now()
	cveIDs, err := fetchOSVVulns(modulePath)
	t.OsvTime += time.Since(t2)
	t.OsvCalls++

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

	return hr, t
}

// Score is the public single-module scorer (kept for external callers).
func Score(modulePath, version string) report.HealthReport {
	hr, _ := scoreWithTiming(modulePath, version)
	return hr
}
