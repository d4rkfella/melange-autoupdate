package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/renovate"
	"chainguard.dev/melange/pkg/renovate/bump"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/google/go-github/v79/github"
)

type VersionResult struct {
	Version   string
	CommitSHA string
}

type CompiledVersionTransform struct {
	Re      *regexp.Regexp
	Replace string
}

func getLatestGitHubVersion(ctx context.Context, logger *slog.Logger, cfg *config.Configuration) (VersionResult, error) {
	gh := cfg.Update.GitHubMonitor
	parts := strings.Split(gh.Identifier, "/")
	if len(parts) != 2 {
		return VersionResult{}, fmt.Errorf("invalid GitHub identifier: %s", gh.Identifier)
	}
	owner, repo := parts[0], parts[1]

	client := github.NewClient(nil)
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		client = client.WithAuthToken(token)
	}

	opts := &github.ListOptions{PerPage: 100}

	compiledIgnore, err := compileIgnorePatterns(cfg.Update.IgnoreRegexPatterns)
	if err != nil {
		return VersionResult{}, fmt.Errorf("compiling ignore patterns: %w", err)
	}

	if gh.UseTags {
		for {
			tags, resp, err := client.Repositories.ListTags(ctx, owner, repo, opts)
			if err != nil {
				return VersionResult{}, fmt.Errorf("fetching tags for %s/%s: %w", owner, repo, err)
			}

			for _, tag := range tags {
				tagName := tag.GetName()

				if gh.GetFilterPrefix() != "" && !strings.HasPrefix(tagName, gh.GetFilterPrefix()) {
					continue
				}
				if gh.GetFilterContains() != "" && !strings.Contains(tagName, gh.GetFilterContains()) {
					continue
				}
				if matchesAnyPattern(compiledIgnore, tagName) {
					logger.Info("ignoring version", "version", tagName, "reason", "matched ignore pattern")
					continue
				}

				processed := strings.TrimPrefix(tagName, gh.GetStripPrefix())
				processed = strings.TrimSuffix(processed, gh.GetStripSuffix())

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
					Version:   processed,
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
				return VersionResult{}, fmt.Errorf("fetching releases for %s/%s: %w", owner, repo, err)
			}

			for _, release := range releases {
				tagName := release.GetTagName()
				if !cfg.Update.EnablePreReleaseTags && release.GetPrerelease() {
					continue
				}
				if gh.GetFilterPrefix() != "" && !strings.HasPrefix(tagName, gh.GetFilterPrefix()) {
					continue
				}
				if gh.GetFilterContains() != "" && !strings.Contains(tagName, gh.GetFilterContains()) {
					continue
				}
				if matchesAnyPattern(compiledIgnore, tagName) {
					logger.Info("ignoring version", "version", tagName, "reason", "matched ignore pattern")
					continue
				}

				processed := strings.TrimPrefix(tagName, gh.GetStripPrefix())
				processed = strings.TrimSuffix(processed, gh.GetStripSuffix())

				sha := ""
				ref, _, err := client.Git.GetRef(ctx, owner, repo, "refs/tags/"+tagName)
				if err == nil && ref.Object != nil {
					sha = ref.Object.GetSHA()
				}

				return VersionResult{
					Version:   processed,
					CommitSHA: sha,
				}, nil
			}

			if resp.NextPage == 0 {
				break
			}
			opts.Page = resp.NextPage
		}
	}

	return VersionResult{}, fmt.Errorf("no valid versions found after filtering for %s/%s", owner, repo)
}

func getLatestGitVersion(ctx context.Context, logger *slog.Logger, cfg *config.Configuration) (VersionResult, error) {
	git := cfg.Update.GitMonitor

	repoURL := ""
	for _, step := range cfg.Pipeline {
		if step.Uses == "git-checkout" {
			if repo := step.With["repository"]; repo != "" {
				repoURL = repo
				break
			}
		}
	}

	if repoURL == "" {
		return VersionResult{}, fmt.Errorf("no git-checkout step found in pipeline")
	}

	logger.Debug("using first git-checkout step for git provider", "repository", repoURL)

	tags, err := gitListRemoteTags(ctx, repoURL)
	if err != nil {
		return VersionResult{}, fmt.Errorf("listing remote tags for %s: %w", repoURL, err)
	}

	if len(tags) == 0 {
		return VersionResult{}, fmt.Errorf("no tags found in repository %s", repoURL)
	}

	compiledIgnore, err := compileIgnorePatterns(cfg.Update.IgnoreRegexPatterns)
	if err != nil {
		return VersionResult{}, fmt.Errorf("compiling ignore patterns: %w", err)
	}

	for _, tag := range tags {
		tagName := tag.Name

		if git.GetFilterPrefix() != "" && !strings.HasPrefix(tagName, git.GetFilterPrefix()) {
			continue
		}
		if git.GetFilterContains() != "" && !strings.Contains(tagName, git.GetFilterContains()) {
			continue
		}
		if matchesAnyPattern(compiledIgnore, tagName) {
			logger.Info("ignoring version", "version", tagName, "reason", "matched ignore pattern")
			continue
		}

		processed := strings.TrimPrefix(tagName, git.GetStripPrefix())
		processed = strings.TrimSuffix(processed, git.GetStripSuffix())

		return VersionResult{
			Version:   processed,
			CommitSHA: tag.SHA,
		}, nil
	}

	return VersionResult{}, fmt.Errorf("no valid versions found after filtering for %s", repoURL)
}

func gitListRemoteTags(ctx context.Context, repoURL string) ([]struct {
	Name string
	SHA  string
}, error) {
	storage := memory.NewStorage()

	rem := git.NewRemote(storage, &gitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{repoURL},
	})

	err := rem.FetchContext(ctx, &git.FetchOptions{
		RefSpecs: []gitconfig.RefSpec{"refs/tags/*:refs/tags/*"},
		Depth:    1, // minimize transfer
	})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return nil, fmt.Errorf("fetching tags: %w", err)
	}

	refs, err := storage.IterReferences()
	if err != nil {
		return nil, fmt.Errorf("iter refs: %w", err)
	}

	type tagWithTime struct {
		Name string
		SHA  string
		Time time.Time
	}

	var tagsWithTime []tagWithTime

	err = refs.ForEach(func(ref *plumbing.Reference) error {
		if !ref.Name().IsTag() {
			return nil
		}

		name := ref.Name().Short()
		sha := ref.Hash()

		var when time.Time

		if tagObj, err := object.GetTag(storage, sha); err == nil {
			when = tagObj.Tagger.When
		} else if commitObj, err := object.GetCommit(storage, sha); err == nil {
			when = commitObj.Committer.When
		}

		tagsWithTime = append(tagsWithTime, tagWithTime{
			Name: name,
			SHA:  sha.String(),
			Time: when,
		})

		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(tagsWithTime, func(i, j int) bool {
		return tagsWithTime[i].Time.After(tagsWithTime[j].Time)
	})

	out := make([]struct {
		Name string
		SHA  string
	}, len(tagsWithTime))

	for i, t := range tagsWithTime {
		out[i] = struct {
			Name string
			SHA  string
		}{
			Name: t.Name,
			SHA:  t.SHA,
		}
	}

	return out, nil
}

func getLatestReleaseMonitorVersion(ctx context.Context, logger *slog.Logger, cfg *config.Configuration) (VersionResult, error) {
	rm := cfg.Update.ReleaseMonitor
	url := fmt.Sprintf("https://release-monitoring.org/api/v2/versions/?project_id=%d", rm.Identifier)

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
	)
	opts, err := testChromiumSandboxing(ctx, logger, opts...)
	if err != nil {
		return VersionResult{}, err
	}

	allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	defer cancel()

	chromeCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	chromeCtx, cancel = context.WithTimeout(chromeCtx, 15*time.Second)
	defer cancel()

	token := os.Getenv("RELEASE_MONITOR_TOKEN")
	headers := map[string]any{
		"User-Agent":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
		"Authorization": "Bearer " + token,
	}

	var jsonBody string

	err = chromedp.Run(chromeCtx,
		network.Enable(),
		network.SetExtraHTTPHeaders(network.Headers(headers)),
		chromedp.Navigate(url),
		chromedp.WaitVisible("body", chromedp.ByQuery),
		chromedp.Evaluate(`document.body.innerText`, &jsonBody),
	)
	if err != nil {
		return VersionResult{}, fmt.Errorf("failed to fetch project info from release-monitoring.org: %w", err)
	}

	var project struct {
		LatestVersion  string   `json:"latest_version"`
		Versions       []string `json:"versions"`
		StableVersions []string `json:"stable_versions"`
	}

	if err := json.Unmarshal([]byte(jsonBody), &project); err != nil {
		logger.Debug("json decode failed", "error", err, "response_preview", truncateString(jsonBody, 200))
		return VersionResult{}, fmt.Errorf("failed to decode response body: %w", err)
	}

	var versions []string
	if !cfg.Update.EnablePreReleaseTags {
		versions = project.StableVersions
	} else {
		versions = project.Versions
	}

	if len(versions) == 0 {
		return VersionResult{}, fmt.Errorf("no versions found in response from release-monitoring.org")
	}

	compiledIgnore, err := compileIgnorePatterns(cfg.Update.IgnoreRegexPatterns)
	if err != nil {
		return VersionResult{}, fmt.Errorf("compiling ignore patterns: %w", err)
	}

	for _, version := range versions {
		if rm.GetFilterPrefix() != "" && !strings.HasPrefix(version, rm.GetFilterPrefix()) {
			continue
		}
		if rm.GetFilterContains() != "" && !strings.Contains(version, rm.GetFilterContains()) {
			continue
		}
		if matchesAnyPattern(compiledIgnore, version) {
			logger.Info("ignoring version", "version", version, "reason", "matched ignore pattern")
			continue
		}

		processed := strings.TrimPrefix(version, rm.GetStripPrefix())
		processed = strings.TrimSuffix(processed, rm.GetStripSuffix())

		return VersionResult{
			Version:   processed,
			CommitSHA: "",
		}, nil
	}

	return VersionResult{}, fmt.Errorf("no valid versions found after filtering")
}

func testChromiumSandboxing(ctx context.Context, logger *slog.Logger, opts ...chromedp.ExecAllocatorOption) ([]chromedp.ExecAllocatorOption, error) {
	allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	defer cancel()
	testCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()
	testCtx, cancel = context.WithTimeout(testCtx, 5*time.Second)
	defer cancel()

	err := chromedp.Run(testCtx, chromedp.Navigate("about:blank"))
	if err == nil {
		return opts, nil
	}

	errStr := err.Error()
	isSandboxError := strings.Contains(errStr, "sandbox") ||
		strings.Contains(errStr, "SUID") ||
		strings.Contains(errStr, "namespace") ||
		strings.Contains(errStr, "setuid") ||
		strings.Contains(errStr, "permission denied")

	if !isSandboxError {
		return nil, err
	}

	logger.Warn("Chromium could not start with sandbox, likely due to CI/container restrictions; using --no-sandbox as fallback")
	opts = append(opts, chromedp.Flag("no-sandbox", true))

	return opts, nil
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "... (truncated)"
}

func matchesAnyPattern(patterns []*regexp.Regexp, s string) bool {
	for _, re := range patterns {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func compileIgnorePatterns(patterns []string) ([]*regexp.Regexp, error) {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid ignore pattern regex %q: %w", p, err)
		}
		compiled = append(compiled, re)
	}
	return compiled, nil
}

func compileVersionTransforms(vts []config.VersionTransform) ([]CompiledVersionTransform, error) {
	out := make([]CompiledVersionTransform, 0, len(vts))
	for _, t := range vts {
		re, err := regexp.Compile(t.Match)
		if err != nil {
			return nil, fmt.Errorf("invalid version transform regex %q: %w", t.Match, err)
		}
		out = append(out, CompiledVersionTransform{
			Re:      re,
			Replace: t.Replace,
		})
	}
	return out, nil
}

func applyCompiledVersionTransforms(version string, transforms []CompiledVersionTransform) string {
	for _, t := range transforms {
		version = t.Re.ReplaceAllString(version, t.Replace)
	}
	return version
}

func compareVersions(logger *slog.Logger, currentStr, latestStr string) int {
	current, err := apk.ParseVersion(currentStr)
	if err != nil {
		logger.Warn("failed to parse current version", "version", currentStr, "error", err)
		return -1
	}

	latest, err := apk.ParseVersion(latestStr)
	if err != nil {
		logger.Warn("failed to parse latest version", "version", latestStr, "error", err)
		return 1
	}
	return apk.CompareVersions(current, latest)
}

func writeOutput(logger *slog.Logger, newVersion, packageName string) error {
	outputFile := os.Getenv("GITHUB_OUTPUT")
	if outputFile == "" {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			return fmt.Errorf("GITHUB_OUTPUT environment variable not set")
		}

		logger.Info("would write to GITHUB_OUTPUT (running locally)",
			"package_version", newVersion,
			"package_name", packageName)
		return nil
	}

	f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open GITHUB_OUTPUT file: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			logger.Warn("failed to close GITHUB_OUTPUT file", "error", cerr)
		}
	}()

	if newVersion != "" {
		if _, err := fmt.Fprintf(f, "package_version=%s\n", newVersion); err != nil {
			return fmt.Errorf("failed to write package_version: %w", err)
		}
	}
	if packageName != "" {
		if _, err := fmt.Fprintf(f, "package_name=%s\n", packageName); err != nil {
			return fmt.Errorf("failed to write package_name: %w", err)
		}
	}

	logger.Debug("wrote outputs to GITHUB_OUTPUT",
		"package_version", newVersion,
		"package_name", packageName)

	return nil
}

func bumpConfig(ctx context.Context, configPath, newVersion, expectedCommit string) error {
	rc, err := renovate.New(renovate.WithConfig(configPath))
	if err != nil {
		return fmt.Errorf("creating renovate client: %w", err)
	}

	ren := bump.New(ctx,
		bump.WithTargetVersion(newVersion),
		bump.WithExpectedCommit(expectedCommit),
	)

	if err := rc.Renovate(ctx, ren); err != nil {
		return fmt.Errorf("renovating config: %w", err)
	}

	return nil
}

func run(ctx context.Context, logger *slog.Logger, filePath string) error {
	cfg, err := config.ParseConfiguration(ctx, filePath)
	if err != nil {
		return fmt.Errorf("parsing configuration: %w", err)
	}

	if !cfg.Update.Enabled {
		logger.Info("updates disabled, skipping", "package", cfg.Package.Name)
		return nil
	}

	compiledTransforms, err := compileVersionTransforms(cfg.Update.VersionTransform)
	if err != nil {
		return fmt.Errorf("compiling version transforms: %w", err)
	}

	var versionResult VersionResult
	if cfg.Update.GitHubMonitor != nil {
		versionResult, err = getLatestGitHubVersion(ctx, logger, cfg)
	} else if cfg.Update.ReleaseMonitor != nil {
		versionResult, err = getLatestReleaseMonitorVersion(ctx, logger, cfg)
	} else if cfg.Update.GitMonitor != nil {
		versionResult, err = getLatestGitVersion(ctx, logger, cfg)
	} else {
		return fmt.Errorf("update provider not implemented")
	}
	if err != nil {
		return fmt.Errorf("fetching latest version: %w", err)
	}

	versionToUse := applyCompiledVersionTransforms(versionResult.Version, compiledTransforms)

	if compareVersions(logger, cfg.Package.Version, versionToUse) >= 0 {
		logger.Info("package version already up to date",
			"current", cfg.Package.Version,
			"latest", versionToUse)
		return nil
	}

	logger.Info("updating package",
		"package", cfg.Package.Name,
		"from", cfg.Package.Version,
		"to", versionToUse)

	if err := bumpConfig(ctx, filePath, versionToUse, versionResult.CommitSHA); err != nil {
		return fmt.Errorf("bumping config: %w", err)
	}

	if err := writeOutput(logger, versionToUse, cfg.Package.Name); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}

	logger.Info("successfully updated package",
		"package", cfg.Package.Name,
		"version", versionToUse)

	return nil
}

func main() {
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	logger := slog.New(handler)

	slog.SetDefault(logger)

	if len(os.Args) < 2 {
		logger.Error("missing argument", "error", "please provide a valid Melange config file path")
		os.Exit(1)
	}
	filePath := os.Args[1]

	ctx := context.Background()
	if err := run(ctx, logger, filePath); err != nil {
		logger.Error("fatal error", "error", err)
		os.Exit(1)
	}
}
