package health

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type ghRepo struct {
	PushedAt   time.Time `json:"pushed_at"`
	Archived   bool      `json:"archived"`
	OpenIssues int       `json:"open_issues_count"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type ghRelease struct {
	PublishedAt time.Time `json:"published_at"`
}

type osvResponse struct {
	Vulns []struct {
		ID      string   `json:"id"`
		Aliases []string `json:"aliases"`
		Summary string   `json:"summary"`
	} `json:"vulns"`
}

func githubToken() string {
	return os.Getenv("GORISK_GITHUB_TOKEN")
}

func ghRequest(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if tok := githubToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	return http.DefaultClient.Do(req)
}

var errRateLimited = fmt.Errorf("github API rate limited — set GORISK_GITHUB_TOKEN to increase limits")

func checkGHStatus(resp *http.Response, context string) error {
	switch resp.StatusCode {
	case 200:
		return nil
	case 429, 403:
		return errRateLimited
	default:
		return fmt.Errorf("github API %d for %s", resp.StatusCode, context)
	}
}

func fetchGHRepo(owner, repo string) (*ghRepo, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo)
	resp, err := ghRequest(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkGHStatus(resp, url); err != nil {
		return nil, err
	}
	var r ghRepo
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

func fetchGHReleases(owner, repo string) ([]ghRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases?per_page=10", owner, repo)
	resp, err := ghRequest(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkGHStatus(resp, "releases"); err != nil {
		return nil, err
	}
	var releases []ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return nil, err
	}
	return releases, nil
}

func fetchOSVVulns(modulePath string) ([]string, error) {
	body := strings.NewReader(fmt.Sprintf(`{"package":{"name":%q,"ecosystem":"Go"}}`, modulePath))
	resp, err := http.Post("https://api.osv.dev/v1/query", "application/json", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(out.Vulns))
	for _, v := range out.Vulns {
		ids = append(ids, v.ID)
	}
	return ids, nil
}

func githubOwnerRepo(modulePath string) (string, string, bool) {
	parts := strings.SplitN(modulePath, "/", 4)
	if len(parts) < 3 {
		return "", "", false
	}
	if parts[0] != "github.com" {
		return "", "", false
	}
	return parts[1], parts[2], true
}
