package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	semver "github.com/Masterminds/semver/v3"
	"gopkg.in/yaml.v3"
)

var numRe = regexp.MustCompile(`\d+`)

type VersionResult struct {
	Original  string
	Processed string
}

type sortableVersion struct {
	Original  string
	Processed string
	SV        *semver.Version
	Parts     []int
}

type Config struct {
	Package       Package        `yaml:"package"`
	Update        Update         `yaml:"update"`
	Pipeline      []PipelineStep `yaml:"pipeline"`
	VarTransforms []VarTransform `yaml:"var-transforms,omitempty"`
	Environment   *Environment   `yaml:"environment,omitempty"`
}

type Environment struct {
	Environment map[string]string `yaml:"environment"`
}

func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type alias Config
	var raw alias
	if err := unmarshal(&raw); err != nil {
		return err
	}

	*c = Config(raw)

	for i := range c.VarTransforms {
		re, err := regexp.Compile(c.VarTransforms[i].Match)
		if err != nil {
			return fmt.Errorf("invalid var-transform regex %q: %w", c.VarTransforms[i].Match, err)
		}
		c.VarTransforms[i].compiled = re
	}

	return nil
}

type Package struct {
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
	Epoch   *int   `yaml:"epoch"`
}

type VersionTransform struct {
	Match    string         `yaml:"match"`
	Replace  string         `yaml:"replace"`
	compiled *regexp.Regexp `yaml:"-"`
}

type VarTransform struct {
	From     string         `yaml:"from"`
	Match    string         `yaml:"match"`
	Replace  string         `yaml:"replace"`
	To       string         `yaml:"to"`
	compiled *regexp.Regexp `yaml:"-"`
}

type Update struct {
	Enabled             bool               `yaml:"enabled"`
	Manual              bool               `yaml:"manual"`
	Shared              bool               `yaml:"shared"`
	RequireSequential   bool               `yaml:"require-sequential"`
	ReleaseMonitor      *ReleaseMonitor    `yaml:"release-monitor,omitempty"`
	GitHub              *GitHub            `yaml:"github,omitempty"`
	Git                 *Git               `yaml:"git,omitempty"`
	IgnoreRegexPatterns []*regexp.Regexp   `yaml:"-"`
	VersionTransforms   []VersionTransform `yaml:"version-transform,omitempty"`
}

func (u *Update) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type alias Update
	var raw struct {
		Data                alias    `yaml:",inline"`
		IgnoreRegexPatterns []string `yaml:"ignore-regex-patterns,omitempty"`
	}

	if err := unmarshal(&raw); err != nil {
		return err
	}

	*u = Update(raw.Data)

	for _, pattern := range raw.IgnoreRegexPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid ignore regex pattern %q: %w", pattern, err)
		}
		u.IgnoreRegexPatterns = append(u.IgnoreRegexPatterns, re)
	}

	for i := range u.VersionTransforms {
		re, err := regexp.Compile(u.VersionTransforms[i].Match)
		if err != nil {
			return fmt.Errorf("invalid version transform regex %q: %w",
				u.VersionTransforms[i].Match, err)
		}
		u.VersionTransforms[i].compiled = re
	}

	return nil
}

type ReleaseMonitor struct {
	Identifier            int    `yaml:"identifier"`
	StripPrefix           string `yaml:"strip-prefix,omitempty"`
	StripSuffix           string `yaml:"strip-suffix,omitempty"`
	VersionFilterPrefix   string `yaml:"version-filter-prefix,omitempty"`
	VersionFilterContains string `yaml:"version-filter-contains,omitempty"`
}

type GitHub struct {
	Identifier        string `yaml:"identifier"`
	StripPrefix       string `yaml:"strip-prefix,omitempty"`
	StripSuffix       string `yaml:"strip-suffix,omitempty"`
	UseTag            bool   `yaml:"use-tag,omitempty"`
	TagFilterPrefix   string `yaml:"tag-filter-prefix,omitempty"`
	TagFilterContains string `yaml:"tag-filter-contains,omitempty"`
}

type Git struct {
	TagFilterPrefix   string `yaml:"tag-filter-prefix,omitempty"`
	StripPrefix       string `yaml:"strip-prefix,omitempty"`
	StripSuffix       string `yaml:"strip-suffix,omitempty"`
	TagFilterContains string `yaml:"tag-filter-contains,omitempty"`
}

type PipelineStep struct {
	Uses string                 `yaml:"uses"`
	With map[string]interface{} `yaml:"with"`
}

var httpClient = &http.Client{
	Timeout: 15 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func parseGitHubRepo(repoURL string, expectedIdentifier string) (owner, repo string, err error) {
	if !strings.HasPrefix(repoURL, "http://") && !strings.HasPrefix(repoURL, "https://") {
		return "", "", fmt.Errorf("invalid repo URL %q: missing scheme (http:// or https://)", repoURL)
	}

	u, err := url.Parse(repoURL)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse repo URL %q: %v", repoURL, err)
	}

	if u.Host != "github.com" {
		return "", "", fmt.Errorf("invalid GitHub URL %q: host must be github.com", repoURL)
	}

	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid GitHub path %q: must be /owner/repo", u.Path)
	}

	owner, repo = parts[0], parts[1]

	if expectedIdentifier != "" {
		expectedParts := strings.Split(expectedIdentifier, "/")
		if len(expectedParts) == 2 {
			if expectedParts[0] != owner || expectedParts[1] != repo {
				return "", "", fmt.Errorf(
					"repo URL %q does not match update identifier %q", repoURL, expectedIdentifier,
				)
			}
		}
	}

	return owner, repo, nil
}

func getGitCheckoutTag(version string, pipeline []PipelineStep) string {
	for _, step := range pipeline {
		if step.Uses == "git-checkout" {
			if tagTemplate, ok := step.With["tag"].(string); ok && tagTemplate != "" {
				prefix := strings.ReplaceAll(tagTemplate, "${{package.version}}", "")
				if !strings.HasPrefix(version, prefix) {
					return prefix + version
				}
				return version
			}
		}
	}
	return version
}

func fetchGitHubCommitHash(owner, repo, originalVersion string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/git/refs/tags/%s", owner, repo, originalVersion)
	log.Printf("INFO: fetching GitHub ref for URL: %s", url)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	addGitHubHeaders(req)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", handleGitHubError(resp)
	}

	var refData struct {
		Object struct {
			Type string `json:"type"`
			SHA  string `json:"sha"`
			URL  string `json:"url"`
		} `json:"object"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&refData); err != nil {
		return "", err
	}

	if refData.Object.Type == "tag" {
		return fetchAnnotatedTagCommit(refData.Object.URL)
	}

	return refData.Object.SHA, nil
}

func fetchAnnotatedTagCommit(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	addGitHubHeaders(req)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var tagData struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tagData); err != nil {
		return "", err
	}

	return tagData.Object.SHA, nil
}

func getLatestReleaseMonitorVersion(update *Update, includePreReleases bool) (VersionResult, error) {
	rm := update.ReleaseMonitor
	url := fmt.Sprintf("https://release-monitoring.org/api/v2/versions/?project_id=%d", rm.Identifier)

	resp, err := httpClient.Get(url)
	if err != nil {
		return VersionResult{}, fmt.Errorf("failed to fetch project info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return VersionResult{}, fmt.Errorf("release-monitoring API error (%d): %s", resp.StatusCode, string(body))
	}

	var project struct {
		Versions       []string `json:"versions"`
		StableVersions []string `json:"stable_versions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&project); err != nil {
		return VersionResult{}, fmt.Errorf("failed to decode project data: %w", err)
	}

	var versions []string
	if includePreReleases {
		versions = project.Versions
	} else {
		versions = project.StableVersions
	}

	if len(versions) == 0 {
		return VersionResult{}, fmt.Errorf("no valid versions found")
	}

	filtered := filterAndProcessVersions(
		versions,
		update.IgnoreRegexPatterns,
		rm.StripPrefix,
		rm.StripSuffix,
		rm.VersionFilterPrefix,
		rm.VersionFilterContains,
	)

	if len(filtered) == 0 {
		return VersionResult{}, fmt.Errorf("no valid versions found after filtering")
	}

	sort.Slice(filtered, func(i, j int) bool {
		return compareVersions(filtered[i].Processed, filtered[j].Processed) < 0
	})

	latest := filtered[len(filtered)-1]
	log.Printf("INFO: latest version selected for comparison: %s (after processing: %s)", latest.Original, latest.Processed)
	return latest, nil
}

func getLatestGitHubVersion(update *Update, includePreReleases bool) (VersionResult, error) {
	gh := update.GitHub
	parts := strings.Split(gh.Identifier, "/")
	if len(parts) != 2 {
		return VersionResult{}, fmt.Errorf("invalid GitHub identifier: %s", gh.Identifier)
	}
	owner, repo := parts[0], parts[1]

	baseURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/", owner, repo)
	var tagNames []string
	page := 1

	if gh.UseTag {
		for {
			url := fmt.Sprintf("%stags?page=%d&per_page=100", baseURL, page)
			req, _ := http.NewRequest("GET", url, nil)
			addGitHubHeaders(req)
			resp, err := httpClient.Do(req)
			if err != nil {
				return VersionResult{}, err
			}
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				return VersionResult{}, handleGitHubError(resp)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			var pageResults []struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(body, &pageResults); err != nil {
				return VersionResult{}, err
			}
			if len(pageResults) == 0 {
				break
			}
			for _, r := range pageResults {
				tagNames = append(tagNames, r.Name)
			}
			page++
		}
	} else {
		for {
			url := fmt.Sprintf("%sreleases?page=%d&per_page=100", baseURL, page)
			req, _ := http.NewRequest("GET", url, nil)
			addGitHubHeaders(req)
			resp, err := httpClient.Do(req)
			if err != nil {
				return VersionResult{}, err
			}
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				return VersionResult{}, handleGitHubError(resp)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			var pageResults []struct {
				TagName    string `json:"tag_name"`
				Prerelease bool   `json:"prerelease"`
			}
			if err := json.Unmarshal(body, &pageResults); err != nil {
				return VersionResult{}, err
			}
			if len(pageResults) == 0 {
				break
			}
			for _, r := range pageResults {
				if !includePreReleases && r.Prerelease {
					log.Printf("INFO skipping pre-release: %s", r.TagName)
					continue
				}
				tagNames = append(tagNames, r.TagName)
			}
			page++
		}
	}

	filtered := filterAndProcessVersions(
		tagNames,
		update.IgnoreRegexPatterns,
		gh.StripPrefix,
		gh.StripSuffix,
		gh.TagFilterPrefix,
		gh.TagFilterContains,
	)
	if len(filtered) == 0 {
		return VersionResult{}, fmt.Errorf("no valid versions found after applying filtering")
	}

	all := make([]sortableVersion, 0, len(filtered))
	for _, v := range filtered {
		sv := sortableVersion{
			Original:  v.Original,
			Processed: v.Processed,
		}
		if full, err := semver.StrictNewVersion(v.Processed); err == nil {
			sv.SV = full
		} else {
			nums := numRe.FindAllString(v.Processed, -1)
			sv.Parts = make([]int, len(nums))
			for i, s := range nums {
				sv.Parts[i], _ = strconv.Atoi(s)
			}
		}
		all = append(all, sv)
	}

	sort.Slice(all, func(i, j int) bool {
		a, b := all[i], all[j]
		var sa, sb []int

		if a.SV != nil {
			sa = []int{int(a.SV.Major()), int(a.SV.Minor()), int(a.SV.Patch())}
		} else {
			sa = a.Parts
		}
		if b.SV != nil {
			sb = []int{int(b.SV.Major()), int(b.SV.Minor()), int(b.SV.Patch())}
		} else {
			sb = b.Parts
		}

		for k := 0; k < len(sa) && k < len(sb); k++ {
			if sa[k] != sb[k] {
				return sa[k] < sb[k]
			}
		}
		if len(sa) != len(sb) {
			return len(sa) < len(sb)
		}
		if a.SV != nil && b.SV != nil {
			return a.SV.LessThan(b.SV)
		}
		return false
	})

	picked := all[len(all)-1]
	log.Printf("INFO: selected latest version: %s", picked.Original)

	return VersionResult{
		Original:  picked.Original,
		Processed: picked.Processed,
	}, nil
}

func filterAndProcessVersions(
	inputs []string,
	ignorePatterns []*regexp.Regexp,
	stripPrefix, stripSuffix, filterPrefix, filterContains string,
) []VersionResult {
	var versions []VersionResult

	for _, original := range inputs {
		if filterPrefix != "" && !strings.HasPrefix(original, filterPrefix) {
			continue
		}
		if filterContains != "" && !strings.Contains(original, filterContains) {
			continue
		}
		if matchesAnyPattern(ignorePatterns, original) {
			log.Printf("INFO ignoring version %q (matched ignore pattern)", original)
			continue
		}

		processed := strings.TrimPrefix(original, stripPrefix)
		processed = strings.TrimSuffix(processed, stripSuffix)
		versions = append(versions, VersionResult{Original: original, Processed: processed})
	}

	return versions
}

func matchesAnyPattern(patterns []*regexp.Regexp, s string) bool {
	for _, re := range patterns {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func applyVersionTransforms(version string, transforms []VersionTransform) string {
	for _, t := range transforms {
		version = t.compiled.ReplaceAllString(version, t.Replace)
	}
	return version
}

func compareVersions(currentStr, latestStr string) int {
	currentSemver, errCurrent := semver.NewVersion(currentStr)
	latestSemver, errLatest := semver.NewVersion(latestStr)

	if errCurrent == nil && errLatest == nil {
		return currentSemver.Compare(latestSemver)
	}

	return naturalCompare(currentStr, latestStr)
}

func naturalCompare(a, b string) int {
	aParts := strings.FieldsFunc(a, func(r rune) bool { return !unicode.IsNumber(r) })
	bParts := strings.FieldsFunc(b, func(r rune) bool { return !unicode.IsNumber(r) })

	for i := 0; i < len(aParts) && i < len(bParts); i++ {
		aNum, aErr := strconv.Atoi(aParts[i])
		bNum, bErr := strconv.Atoi(bParts[i])

		if aErr == nil && bErr == nil {
			if aNum != bNum {
				return aNum - bNum
			}
			continue
		}

		cmp := strings.Compare(aParts[i], bParts[i])
		if cmp != 0 {
			return cmp
		}
	}

	return len(aParts) - len(bParts)
}

func addGitHubHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "melange-updater/1.0")
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

func handleGitHubError(resp *http.Response) error {
	if resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") == "0" {
		resetTime := resp.Header.Get("X-RateLimit-Reset")
		if resetTime != "" {
			if resetInt, err := strconv.ParseInt(resetTime, 10, 64); err == nil {
				reset := time.Unix(resetInt, 0).Format(time.RFC1123)
				return fmt.Errorf("GitHub API rate limit exceeded, resets at %s", reset)
			}
		}
		return fmt.Errorf("GitHub API rate limit exceeded")
	}
	return fmt.Errorf("GitHub API returned status %s", resp.Status)
}

func isStrictSameFormat(a, b string) bool {
	aSegments, aSeps := splitVersionStrict(a)
	bSegments, bSeps := splitVersionStrict(b)

	if len(aSegments) != len(bSegments) || len(aSeps) != len(bSeps) {
		return false
	}

	for i := range aSegments {
		if isNumeric(aSegments[i]) != isNumeric(bSegments[i]) {
			return false
		}
	}

	for i := range aSeps {
		if aSeps[i] != bSeps[i] {
			return false
		}
	}

	return true
}

func splitVersionStrict(v string) (segments []string, separators []string) {
	var current strings.Builder
	for i := 0; i < len(v); i++ {
		if isSeparator(v[i]) {
			segments = append(segments, current.String())
			current.Reset()
			separators = append(separators, string(v[i]))
		} else {
			current.WriteByte(v[i])
		}
	}
	segments = append(segments, current.String())
	return
}

func isSeparator(c byte) bool {
	return c == '.' || c == '-' || c == '_' || c == '+'
}

func isNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

func writeOutput(newVersion, packageName string, bumped bool) {
	outputPath := "output.json"

	updateInfo := struct {
		Bumped      bool   `json:"bumped"`
		PackageName string `json:"package_name"`
		NewVersion  string `json:"new_version"`
	}{
		Bumped:      bumped,
		PackageName: packageName,
		NewVersion:  newVersion,
	}

	data, err := json.MarshalIndent(updateInfo, "", "  ")
	if err != nil {
		log.Fatalf("ERROR: Failed to serialize version update info: %v", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		log.Fatalf("ERROR: Failed to write version update output file to %s: %v", outputPath, err)
	}
}

func reconstructPackageVersion(config *Config) string {
	version := config.Package.Version

	var filterVarTransforms []VarTransform
	for _, transform := range config.VarTransforms {
		if transform.From == "${{package.version}}" {
			filterVarTransforms = append(filterVarTransforms, transform)
		}
	}

	tagUsesTransform := map[string]bool{}
	for _, step := range config.Pipeline {
		if step.Uses == "git-checkout" {
			if tag, ok := step.With["tag"].(string); ok {
				for _, transform := range filterVarTransforms {
					placeholder := fmt.Sprintf("${{vars.%s}}", transform.To)
					if strings.Contains(tag, placeholder) {
						tagUsesTransform[transform.To] = true
					}
				}
			}
		}
	}

	for _, transform := range filterVarTransforms {
		if !tagUsesTransform[transform.To] {
			log.Printf("INFO: skipping var transform '%s' — not used in git-checkout step", transform.To)
			continue
		}

		if transform.compiled.MatchString(version) {
			transformedVersion := transform.compiled.ReplaceAllString(version, transform.Replace)
			log.Printf("INFO: applied transform '%s': %s -> %s", transform.To, version, transformedVersion)
			version = transformedVersion
		}
	}

	if config.Update.GitHub != nil {
		if config.Update.GitHub.StripPrefix != "" {
			version = config.Update.GitHub.StripPrefix + version
		}
		if config.Update.GitHub.StripSuffix != "" {
			version = version + config.Update.GitHub.StripSuffix
		}
	}

	if config.Update.ReleaseMonitor != nil {
		if config.Update.ReleaseMonitor.StripPrefix != "" {
			version = config.Update.ReleaseMonitor.StripPrefix + version
		}
		if config.Update.ReleaseMonitor.StripSuffix != "" {
			version = version + config.Update.ReleaseMonitor.StripSuffix
		}
	}

	return version
}

func generatePRBody(owner, repo, currentVersion, newVersion, packageName string) {
	log.Printf("INFO: generating PR body for new version: %s", newVersion)
	prBody := "### 📦 Automated Package Update\n\n"
	prBody += fmt.Sprintf("**Package:** %s\n", packageName)
	prBody += fmt.Sprintf("**Source:** [https://github.com/%s/%s](https://github.com/%s/%s)\n\n", owner, repo, owner, repo)

	releaseNotes, compareURL := generateReleaseNotesOrCompareURL(owner, repo, currentVersion, newVersion)

	if releaseNotes != nil {
		prBody += fmt.Sprintf(
			"\n<details>\n<summary><b>📜 Release Notes</b></summary>\n\n\n%s\n\n</details>\n",
			*releaseNotes,
		)
	} else if compareURL != nil {
		prBody += fmt.Sprintf(
			"\n\n<h3 dir=\"auto\"><a href=\"%s\"><code class=\"notranslate\">%s</code></a></h3>\n\n",
			*compareURL,
			newVersion,
		)
	}

	prBodyPath := "pr_body.md"
	err := os.WriteFile(prBodyPath, []byte(prBody), 0644)
	if err != nil {
		log.Fatalf("failed to write PR body file: %v", err)
	}
}

func generateReleaseNotesOrCompareURL(owner, repo, currentVersion, newVersion string) (*string, *string) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/tags/%s", owner, repo, newVersion)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		log.Printf("WARNING: failed to create request for release notes: %v", err)
		compare := fmt.Sprintf("https://github.com/%s/%s/compare/%s...%s", owner, repo, currentVersion, newVersion)
		return nil, &compare
	}

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("User-Agent", "melange-updater/1.0")

	resp, err := httpClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		log.Printf("WARNING: failed to fetch release notes from GitHub, falling back to compare URL: %v", err)
		compare := fmt.Sprintf("https://github.com/%s/%s/compare/%s...%s", owner, repo, currentVersion, newVersion)
		return nil, &compare
	}
	defer resp.Body.Close()

	var release struct {
		Body string `json:"body"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		log.Printf("WARNING: failed to decode release body, falling back to compare URL: %v", err)
		compare := fmt.Sprintf("https://github.com/%s/%s/compare/%s...%s", owner, repo, currentVersion, newVersion)
		return nil, &compare
	}

	body := strings.TrimSpace(release.Body)
	if body == "" {
		compare := fmt.Sprintf("https://github.com/%s/%s/compare/%s...%s", owner, repo, currentVersion, newVersion)
		return nil, &compare
	}
	body = regexp.MustCompile(`(@[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)?|#[0-9]+)`).ReplaceAllStringFunc(body, func(m string) string { return "`" + m + "`" })

	return &body, nil
}

func runMelangeCommand(filePath, versionToUse, commitHash string) {

	args := []string{"bump", filePath, versionToUse}
	if commitHash != "" {
		args = append(args, "--expected-commit="+commitHash)
	}

	log.Printf("INFO: executing command melange %s\n", strings.Join(args, " "))
	cmd := exec.Command("melange", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("ERROR: unable to execute melange bump command: %v", err)
	}
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("ERROR: please provide a valid Melange config file path")
	}
	filePath := os.Args[1]
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatal(err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Fatalf("ERROR: failed to unmarshal Melange yaml config: %v", err)
	}

	if !config.Update.Enabled {
		log.Printf("WARNING: Updates are disabled for package %s, skipping.", config.Package.Name)
		writeOutput("", "", false)
		return
	}

	includePreReleases := false

	if config.Environment != nil && config.Environment.Environment != nil {
		if val, ok := config.Environment.Environment["PACKAGE_UPDATE_USE_PRERELEASE"]; ok {
			includePreReleases = strings.EqualFold(val, "true") || val == "1"
		}
	}

	var owner, repo, repoURL string
	var expectedCommitNeeded bool

	foundGitCheckoutStep := false

	for _, step := range config.Pipeline {
		if strings.Contains(step.Uses, "git-checkout") {
			foundGitCheckoutStep = true

			if step.With != nil {
				if _, ok := step.With["expected-commit"]; ok {
					expectedCommitNeeded = true
				}
				if r, ok := step.With["repository"].(string); ok {
					repoURL = r
				}
			}
			break
		}
	}

	if foundGitCheckoutStep {
		if repoURL == "" {
			log.Fatal("ERROR: git-checkout step does not have a defined repository")
		}
	
		if config.Update.GitHub != nil {
			owner, repo, err = parseGitHubRepo(repoURL, config.Update.GitHub.Identifier)
			if err != nil {
				log.Fatalf("ERROR: GitHub repo validation failed: %v", err)
			}
		} else {
			owner, repo, err = parseGitHubRepo(repoURL, "")
			if err != nil {
				log.Fatalf("ERROR: failed to parse repository URL: %v", err)
			}
		}
	}

	var versionResult VersionResult
	if config.Update.ReleaseMonitor != nil {
		versionResult, err = getLatestReleaseMonitorVersion(&config.Update, includePreReleases)
	} else if config.Update.GitHub != nil {
		versionResult, err = getLatestGitHubVersion(&config.Update, includePreReleases)
	} else {
		log.Fatal("ERROR: update provider not configured")
	}
	if err != nil {
		log.Fatal(err)
	}

	var versionToUse string
	if len(config.Update.VersionTransforms) > 0 {
		transformedVersion := applyVersionTransforms(versionResult.Processed, config.Update.VersionTransforms)
		versionToUse = transformedVersion
	} else {
		versionToUse = versionResult.Processed
	}

	if !isStrictSameFormat(versionToUse, config.Package.Version) {
		log.Fatalf("ERROR: version format mismatch during comparison.\nlatest version string after processing: %q\nCurrent package version: %q\nPlease review your version transform rules.", versionToUse, config.Package.Version)
	}

	if compareVersions(versionToUse, config.Package.Version) <= 0 {
		log.Printf("INFO: package version already up to date.")
		writeOutput("", "", false)
		return
	}

	currentVersion := reconstructPackageVersion(&config)
	newVersion := getGitCheckoutTag(versionResult.Original, config.Pipeline)
	commitHash := ""

	if expectedCommitNeeded {
		commitHash, err = fetchGitHubCommitHash(owner, repo, newVersion)
		if err != nil {
			log.Fatalf("ERROR: unable to fetch commit hash: %v", err)
		}
	}
	runMelangeCommand(filePath, versionToUse, commitHash)
	generatePRBody(owner, repo, currentVersion, newVersion, config.Package.Name)
	writeOutput(versionToUse, config.Package.Name, true)
}
