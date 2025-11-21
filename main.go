package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"regexp"
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

type versionResult struct {
	Version   string
	CommitSHA string
}

type tagRef struct {
	Name string
	Hash plumbing.Hash
}

type compiledVersionTransform struct {
	Re      *regexp.Regexp
	Replace string
}

type versionCandidate struct {
	Original  string
	Processed string
	ApkVer    apk.Version
}

type versionFilter interface {
	GetFilterPrefix() string
	GetFilterContains() string
	GetStripPrefix() string
	GetStripSuffix() string
}

func filterVersion(name string, filter versionFilter, compiledIgnore []*regexp.Regexp, logger *slog.Logger) bool {
	if p := filter.GetFilterPrefix(); p != "" && !strings.HasPrefix(name, p) {
		return true
	}
	if c := filter.GetFilterContains(); c != "" && !strings.Contains(name, c) {
		return true
	}

	for _, re := range compiledIgnore {
		if re.MatchString(name) {
			logger.Debug("ignoring version", "version", name, "reason", "matched ignore pattern")
			return true
		}
	}

	return false
}

func transformVersion(name string, filter versionFilter, transforms []compiledVersionTransform) string {
	processed := strings.TrimPrefix(name, filter.GetStripPrefix())
	processed = strings.TrimSuffix(processed, filter.GetStripSuffix())

	for _, t := range transforms {
		processed = t.Re.ReplaceAllString(processed, t.Replace)
	}

	return processed
}

func findLatestValidVersion(
	versions []string,
	filter versionFilter,
	compiledIgnore []*regexp.Regexp,
	transforms []compiledVersionTransform,
	logger *slog.Logger,
) (*versionCandidate, error) {
	var winner *versionCandidate

	for _, verStr := range versions {
		if filterVersion(verStr, filter, compiledIgnore, logger) {
			continue
		}

		processed := transformVersion(verStr, filter, transforms)

		ver, err := apk.ParseVersion(processed)
		if err != nil {
			logger.Info("skipping version, cannot parse as apk version",
				"version", verStr,
				"processed", processed,
				"error", err)
			continue
		}

		if winner == nil || apk.CompareVersions(ver, winner.ApkVer) > 0 {
			winner = &versionCandidate{
				Original:  verStr,
				Processed: processed,
				ApkVer:    ver,
			}
		}
	}

	if winner == nil {
		return nil, fmt.Errorf("no valid versions found after filtering and parsing")
	}

	return winner, nil
}

func getLatestGitHubVersion(ctx context.Context, logger *slog.Logger, cfg *config.Configuration, melangeTransforms []compiledVersionTransform) (versionResult, error) {
	gh := cfg.Update.GitHubMonitor
	parts := strings.Split(gh.Identifier, "/")
	if len(parts) != 2 {
		return versionResult{}, fmt.Errorf("invalid GitHub identifier: %s", gh.Identifier)
	}
	owner, repo := parts[0], parts[1]

	client := github.NewClient(nil)
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		client = client.WithAuthToken(token)
	}

	opts := &github.ListOptions{PerPage: 100}

	compiledIgnore, err := compileIgnorePatterns(cfg.Update.IgnoreRegexPatterns)
	if err != nil {
		return versionResult{}, fmt.Errorf("compiling ignore patterns: %w", err)
	}

	resolveSHA := func(tagName string) (string, error) {
		ref, _, err := client.Git.GetRef(ctx, owner, repo, "refs/tags/"+tagName)
		if err != nil {
			return "", fmt.Errorf("fetching ref for tag %s: %w", tagName, err)
		}
		if ref.Object == nil {
			return "", fmt.Errorf("ref object missing for tag %s", tagName)
		}

		switch ref.Object.GetType() {
		case "commit":
			return ref.Object.GetSHA(), nil
		case "tag":
			tagObj, _, err := client.Git.GetTag(ctx, owner, repo, ref.Object.GetSHA())
			if err != nil {
				return "", fmt.Errorf("resolving annotated tag %s: %w", tagName, err)
			}
			if tagObj.Object != nil {
				return tagObj.Object.GetSHA(), nil
			}
		}

		return "", fmt.Errorf("unable to resolve SHA for tag %s", tagName)
	}

	processTags := func(tags []string) (*versionCandidate, error) {
		return findLatestValidVersion(tags, gh, compiledIgnore, melangeTransforms, logger)
	}

	fetchAndReturn := func(winner *versionCandidate) (versionResult, error) {
		sha, err := resolveSHA(winner.Original)
		if err != nil {
			return versionResult{}, err
		}
		return versionResult{
			Version:   winner.Processed,
			CommitSHA: sha,
		}, nil
	}

	if gh.UseTags {
		for {
			tags, resp, err := client.Repositories.ListTags(ctx, owner, repo, opts)
			if err != nil {
				return versionResult{}, fmt.Errorf("listing tags: %w", err)
			}

			tagNames := make([]string, len(tags))
			for i := range tags {
				tagNames[i] = tags[i].GetName()
			}

			winner, err := processTags(tagNames)
			if err == nil && winner != nil {
				return fetchAndReturn(winner)
			}

			if resp.NextPage == 0 {
				break
			}
			opts.Page = resp.NextPage
		}

		return versionResult{}, fmt.Errorf("no valid tags found for %s/%s", owner, repo)
	}

	for {
		releases, resp, err := client.Repositories.ListReleases(ctx, owner, repo, opts)
		if err != nil {
			return versionResult{}, fmt.Errorf("listing releases: %w", err)
		}

		tagNames := make([]string, 0, len(releases))
		for _, r := range releases {
			if !cfg.Update.EnablePreReleaseTags && r.GetPrerelease() {
				continue
			}
			tagNames = append(tagNames, r.GetTagName())
		}

		winner, err := processTags(tagNames)
		if err == nil && winner != nil {
			return fetchAndReturn(winner)
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return versionResult{}, fmt.Errorf("no versions found for %s/%s", owner, repo)
}

func getLatestGitVersion(ctx context.Context, logger *slog.Logger, cfg *config.Configuration, transforms []compiledVersionTransform) (versionResult, error) {
	gitMonitor := cfg.Update.GitMonitor

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
		return versionResult{}, fmt.Errorf("no git-checkout step found in pipeline")
	}
	logger.Debug("using git repository", "repo", repoURL)

	storage := memory.NewStorage()
	rem := git.NewRemote(storage, &gitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{repoURL},
	})

	refs, err := rem.ListContext(ctx, &git.ListOptions{})
	if err != nil {
		return versionResult{}, fmt.Errorf("listing remote refs: %w", err)
	}

	var rawTags []tagRef
	for _, ref := range refs {
		if ref.Name().IsTag() {
			rawTags = append(rawTags, tagRef{
				Name: ref.Name().Short(),
				Hash: ref.Hash(),
			})
			logger.Debug("full tag reference", "ref", fmt.Sprintf("%#v", ref))
		}
	}
	if len(rawTags) == 0 {
		return versionResult{}, fmt.Errorf("no tags found in repository %s", repoURL)
	}

	compiledIgnore, err := compileIgnorePatterns(cfg.Update.IgnoreRegexPatterns)
	if err != nil {
		return versionResult{}, fmt.Errorf("compiling ignore patterns: %w", err)
	}

	tagNames := make([]string, len(rawTags))
	tagHashMap := make(map[string]plumbing.Hash)
	for i, t := range rawTags {
		tagNames[i] = t.Name
		tagHashMap[t.Name] = t.Hash
	}

	winner, err := findLatestValidVersion(tagNames, gitMonitor, compiledIgnore, transforms, logger)
	if err != nil {
		return versionResult{}, err
	}

	refSpec := gitconfig.RefSpec(fmt.Sprintf("refs/tags/%s:refs/tags/%s", winner.Original, winner.Original))
	if err := rem.FetchContext(ctx, &git.FetchOptions{
		RefSpecs: []gitconfig.RefSpec{refSpec},
		Depth:    1,
	}); err != nil && err != git.NoErrAlreadyUpToDate {
		return versionResult{}, fmt.Errorf("fetching tag %s: %w", winner.Original, err)
	}

	winnerHash := tagHashMap[winner.Original]
	commitSHA := ""
	if tagObj, err := object.GetTag(storage, winnerHash); err == nil {
		if commitObj, err := object.GetCommit(storage, tagObj.Target); err == nil {
			commitSHA = commitObj.Hash.String()
		}
	} else if commitObj, err := object.GetCommit(storage, winnerHash); err == nil {
		commitSHA = commitObj.Hash.String()
	}

	if commitSHA == "" {
		return versionResult{}, fmt.Errorf("failed to resolve commit for tag %s", winner.Original)
	}

	return versionResult{
		Version:   winner.Processed,
		CommitSHA: commitSHA,
	}, nil
}

func getLatestReleaseMonitorVersion(ctx context.Context, logger *slog.Logger, cfg *config.Configuration, transforms []compiledVersionTransform) (versionResult, error) {
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
		return versionResult{}, err
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
	if err := chromedp.Run(chromeCtx,
		network.Enable(),
		network.SetExtraHTTPHeaders(network.Headers(headers)),
		chromedp.Navigate(url),
		chromedp.WaitVisible("body", chromedp.ByQuery),
		chromedp.Evaluate(`document.body.innerText`, &jsonBody),
	); err != nil {
		return versionResult{}, fmt.Errorf("failed to fetch project info from release-monitoring.org: %w", err)
	}

	var project struct {
		LatestVersion  string   `json:"latest_version"`
		Versions       []string `json:"versions"`
		StableVersions []string `json:"stable_versions"`
	}

	if err := json.Unmarshal([]byte(jsonBody), &project); err != nil {
		logger.Debug("previewing response", "response_preview", truncateString(jsonBody, 200))
		return versionResult{}, fmt.Errorf("failed to decode response body: %w", err)
	}

	var versions []string
	if !cfg.Update.EnablePreReleaseTags {
		versions = project.StableVersions
	} else {
		versions = project.Versions
	}

	if len(versions) == 0 {
		return versionResult{}, fmt.Errorf("no versions found in response from release-monitoring.org")
	}

	compiledIgnore, err := compileIgnorePatterns(cfg.Update.IgnoreRegexPatterns)
	if err != nil {
		return versionResult{}, fmt.Errorf("compiling ignore patterns: %w", err)
	}

	winner, err := findLatestValidVersion(versions, rm, compiledIgnore, transforms, logger)
	if err != nil {
		return versionResult{}, err
	}

	return versionResult{
		Version:   winner.Processed,
		CommitSHA: "",
	}, nil
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

func compileVersionTransforms(vts []config.VersionTransform) ([]compiledVersionTransform, error) {
	out := make([]compiledVersionTransform, 0, len(vts))
	for _, t := range vts {
		re, err := regexp.Compile(t.Match)
		if err != nil {
			return nil, fmt.Errorf("invalid version transform regex %q: %w", t.Match, err)
		}
		out = append(out, compiledVersionTransform{
			Re:      re,
			Replace: t.Replace,
		})
	}
	return out, nil
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

	var versionResult versionResult
	if cfg.Update.GitHubMonitor != nil {
		versionResult, err = getLatestGitHubVersion(ctx, logger, cfg, compiledTransforms)
	} else if cfg.Update.ReleaseMonitor != nil {
		versionResult, err = getLatestReleaseMonitorVersion(ctx, logger, cfg, compiledTransforms)
	} else if cfg.Update.GitMonitor != nil {
		versionResult, err = getLatestGitVersion(ctx, logger, cfg, compiledTransforms)
	} else {
		return fmt.Errorf("update provider not implemented")
	}
	if err != nil {
		return fmt.Errorf("fetching latest version: %w", err)
	}

	if compareVersions(logger, cfg.Package.Version, versionResult.Version) >= 0 {
		logger.Info("package version already up to date",
			"current", cfg.Package.Version,
			"latest", versionResult.Version)
		return nil
	}

	logger.Info("updating package",
		"package", cfg.Package.Name,
		"from", cfg.Package.Version,
		"to", versionResult.Version)

	if err := bumpConfig(ctx, filePath, versionResult.Version, versionResult.CommitSHA); err != nil {
		return fmt.Errorf("bumping config: %w", err)
	}

	if err := writeOutput(logger, versionResult.Version, cfg.Package.Name); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}

	logger.Info("successfully updated package",
		"package", cfg.Package.Name,
		"version", versionResult.Version)

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
