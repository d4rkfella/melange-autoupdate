package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"chainguard.dev/apko/pkg/apk/apk"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/google/go-github/v79/github"
	"go.yaml.in/yaml/v4"
)

type VersionResult struct {
	Original  string
	Processed string
	CommitSHA string
}

type Config struct {
	Package      Package       `yaml:"package"`
	Update       Update        `yaml:"update"`
	VarTransform *VarTransform `yaml:"var-transforms,omitempty"`
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

func (c *Config) UnmarshalYAML(unmarshal func(any) error) error {
	type rawConfig struct {
		Package       Package        `yaml:"package"`
		Update        Update         `yaml:"update"`
		VarTransforms []VarTransform `yaml:"var-transforms,omitempty"`
	}

	var raw rawConfig
	if err := unmarshal(&raw); err != nil {
		return err
	}

	c.Package = raw.Package
	c.Update = raw.Update

	for _, vt := range raw.VarTransforms {
		if vt.To == "mangled-package-version" {
			re, err := regexp.Compile(vt.Match)
			if err != nil {
				return fmt.Errorf("invalid var-transform regex %q: %w", vt.Match, err)
			}
			vt.compiled = re
			c.VarTransform = &vt
			break
		}
	}

	return nil
}

func (u *Update) UnmarshalYAML(unmarshal func(any) error) error {
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

func getLatestGitHubVersion(update *Update) (VersionResult, error) {
	gh := update.GitHub
	parts := strings.Split(gh.Identifier, "/")
	if len(parts) != 2 {
		return VersionResult{}, fmt.Errorf("invalid GitHub identifier: %s", gh.Identifier)
	}
	owner, repo := parts[0], parts[1]

	ctx := context.Background()
	client := github.NewClient(nil)
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		client = client.WithAuthToken(token)
	}

	opts := &github.ListOptions{PerPage: 100}

	if gh.UseTag {
		for {
			tags, resp, err := client.Repositories.ListTags(ctx, owner, repo, opts)
			if err != nil {
				return VersionResult{}, fmt.Errorf("fetching tags: %w", err)
			}

			for _, tag := range tags {
				tagName := tag.GetName()

				if gh.TagFilterPrefix != "" && !strings.HasPrefix(tagName, gh.TagFilterPrefix) {
					continue
				}
				if gh.TagFilterContains != "" && !strings.Contains(tagName, gh.TagFilterContains) {
					continue
				}
				if matchesAnyPattern(update.IgnoreRegexPatterns, tagName) {
					log.Printf("INFO: ignoring version %q (matched ignore pattern)", tagName)
					continue
				}

				processed := strings.TrimPrefix(tagName, gh.StripPrefix)
				processed = strings.TrimSuffix(processed, gh.StripSuffix)

				sha := ""
				if tag.Commit != nil {
					sha = tag.Commit.GetSHA()
				} else {
					ref, _, err := client.Git.GetRef(ctx, owner, repo, "refs/tags/"+tagName)
					if err == nil && ref.Object != nil {
						sha = ref.Object.GetSHA()
					}
				}

				return VersionResult{
					Original:  tagName,
					Processed: processed,
					CommitSHA: sha,
				}, nil
			}

			if resp.NextPage == 0 {
				break
			}
			opts.Page = resp.NextPage
		}
	} else {
		for {
			releases, resp, err := client.Repositories.ListReleases(ctx, owner, repo, opts)
			if err != nil {
				return VersionResult{}, fmt.Errorf("fetching releases: %w", err)
			}

			for _, release := range releases {

				tagName := release.GetTagName()

				if gh.TagFilterPrefix != "" && !strings.HasPrefix(tagName, gh.TagFilterPrefix) {
					continue
				}
				if gh.TagFilterContains != "" && !strings.Contains(tagName, gh.TagFilterContains) {
					continue
				}
				if matchesAnyPattern(update.IgnoreRegexPatterns, tagName) {
					log.Printf("INFO: ignoring version %q (matched ignore pattern)", tagName)
					continue
				}

				processed := strings.TrimPrefix(tagName, gh.StripPrefix)
				processed = strings.TrimSuffix(processed, gh.StripSuffix)

				sha := ""
				ref, _, err := client.Git.GetRef(ctx, owner, repo, "refs/tags/"+tagName)
				if err == nil && ref.Object != nil {
					sha = ref.Object.GetSHA()
				}

				return VersionResult{
					Original:  tagName,
					Processed: processed,
					CommitSHA: sha,
				}, nil
			}

			if resp.NextPage == 0 {
				break
			}
			opts.Page = resp.NextPage
		}
	}

	return VersionResult{}, fmt.Errorf("no valid versions found after filtering")
}

func getLatestReleaseMonitorVersion(update *Update) (VersionResult, error) {
	rm := update.ReleaseMonitor
	url := fmt.Sprintf("https://release-monitoring.org/api/v2/versions/?project_id=%d", rm.Identifier)

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
	)
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	token := os.Getenv("RELEASE_MONITOR_TOKEN")
	headers := map[string]any{
		"User-Agent":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
		"Authorization": "Bearer " + token,
	}

	var jsonBody string

	err := chromedp.Run(ctx,
		network.Enable(),
		network.SetExtraHTTPHeaders(network.Headers(headers)),

		chromedp.Navigate(url),
		chromedp.WaitVisible("body", chromedp.ByQuery),
		chromedp.Evaluate(`document.body.innerText`, &jsonBody),
	)
	if err != nil {
		return VersionResult{}, fmt.Errorf("failed to fetch project info: %w", err)
	}

	var project struct {
		LatestVersion  string   `json:"latest_version"`
		Versions       []string `json:"versions"`
		StableVersions []string `json:"stable_versions"`
	}

	if err := json.Unmarshal([]byte(jsonBody), &project); err != nil {
		log.Printf("DEBUG: Response body: %s", jsonBody)
		return VersionResult{}, fmt.Errorf("failed to decode project data: %w", err)
	}

	versions := project.Versions

	if len(versions) == 0 {
		return VersionResult{}, fmt.Errorf("no versions found in response")
	}

	for _, version := range versions {
		if rm.VersionFilterPrefix != "" && !strings.HasPrefix(version, rm.VersionFilterPrefix) {
			continue
		}
		if rm.VersionFilterContains != "" && !strings.Contains(version, rm.VersionFilterContains) {
			continue
		}
		if matchesAnyPattern(update.IgnoreRegexPatterns, version) {
			log.Printf("INFO: ignoring version %q (matched ignore pattern)", version)
			continue
		}

		processed := strings.TrimPrefix(version, rm.StripPrefix)
		processed = strings.TrimSuffix(processed, rm.StripSuffix)

		return VersionResult{
			Original:  version,
			Processed: processed,
			CommitSHA: "",
		}, nil
	}

	return VersionResult{}, fmt.Errorf("no valid versions found after filtering")
}

func matchesAnyPattern(patterns []*regexp.Regexp, s string) bool {
	for _, re := range patterns {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func applyVersionTransform(version string, t *VarTransform) string {
	if t != nil && t.compiled != nil {
		return t.compiled.ReplaceAllString(version, t.Replace)
	}
	return version
}

func compareVersions(currentStr, latestStr string) int {
	current, err := apk.ParseVersion(currentStr)
	if err != nil {
		log.Printf("WARNING: failed to parse current version %q: %v", currentStr, err)
		return -1
	}

	latest, err := apk.ParseVersion(latestStr)
	if err != nil {
		log.Printf("WARNING: failed to parse latest version %q: %v", latestStr, err)
		return 1
	}
	return apk.CompareVersions(current, latest)
}

func writeOutput(newVersion, packageName string) {
	outputFile := os.Getenv("GITHUB_OUTPUT")
	if outputFile == "" {
		log.Println("WARNING: GITHUB_OUTPUT not set, skip writing outputs")
		return
	}

	f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("ERROR: failed to open GITHUB_OUTPUT file: %v", err)
	}
	defer f.Close()

	if newVersion != "" {
		fmt.Fprintf(f, "package_version=%s\n", newVersion)
	}
	if packageName != "" {
		fmt.Fprintf(f, "package_name=%s\n", packageName)
	}
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
		return
	}

	var versionResult VersionResult
	if config.Update.GitHub != nil {
		versionResult, err = getLatestGitHubVersion(&config.Update)
	} else if config.Update.ReleaseMonitor != nil {
		versionResult, err = getLatestReleaseMonitorVersion(&config.Update)
	} else {
		log.Fatal("ERROR: update provider not configured")
	}
	if err != nil {
		log.Fatal(err)
	}

	versionToUse := applyVersionTransform(versionResult.Processed, config.VarTransform)

	if compareVersions(config.Package.Version, versionToUse) >= 0 {
		log.Printf("INFO: package version already up to date.")
		return
	}

	runMelangeCommand(filePath, versionToUse, versionResult.CommitSHA)
	writeOutput(versionToUse, config.Package.Name)
}
