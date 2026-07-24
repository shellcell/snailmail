package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/shellcell/snailmail/engine"
)

const defaultGeneratedAt = "1970-01-01T00:00:00Z"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "snailmail: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stdout)
		return nil
	}
	switch args[0] {
	case "init":
		return runInit(args[1:], stdout, stderr)
	case "setup":
		return runSetup(args[1:], stdout, stderr)
	case "add":
		return runAdd(args[1:], stdout, stderr)
	case "plan":
		return runPlan(ctx, args[1:], stdout, stderr)
	case "apply":
		return runApply(ctx, args[1:], stdout, stderr)
	case "build":
		return runBuild(ctx, args[1:], stdout, stderr)
	case "verify":
		return runVerify(ctx, args[1:], stdout, stderr)
	case "serve":
		return runServe(ctx, args[1:], stdout, stderr)
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runInit(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	workspace := flags.String("workspace", ".", "workspace root")
	name := flags.String("name", "", "workspace name")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if err := engine.InitWorkspace(engine.InitWorkspaceRequest{Root: *workspace, Name: *name}); err != nil {
		return err
	}
	printBrand(stdout)
	fmt.Fprintf(stdout, "✉️   initialized workspace %s\n", *name)
	return nil
}

func runSetup(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: snailmail setup <pypi|deb|helm> --name NAME --output DIR")
	}
	format := args[0]
	flags := flag.NewFlagSet("setup "+format, flag.ContinueOnError)
	flags.SetOutput(stderr)
	workspace := flags.String("workspace", ".", "workspace root")
	name := flags.String("name", "", "repository name")
	output := flags.String("output", "", "workspace-relative published directory")
	suite := flags.String("suite", "stable", "Debian suite")
	component := flags.String("component", "main", "Debian component")
	architectures := flags.String("architectures", "amd64", "comma-separated Debian architectures")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if err := engine.SetupRepository(engine.SetupRepositoryRequest{
		Root: *workspace, Name: *name, Format: format, Output: *output,
		Suite: *suite, Component: *component, Architectures: splitList(*architectures),
	}); err != nil {
		return err
	}
	printBrand(stdout)
	fmt.Fprintf(stdout, "📦  configured %s repository %s\n", format, *name)
	fmt.Fprintf(stdout, "✉️   desired state will publish to %s\n", *output)
	return nil
}

func runAdd(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("add", flag.ContinueOnError)
	flags.SetOutput(stderr)
	workspace := flags.String("workspace", ".", "workspace root")
	track := flags.String("track", "stable", "placement track")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() < 2 {
		return errors.New("usage: snailmail add [--track stable] REPOSITORY ARTIFACT...")
	}
	result, err := engine.AddArtifacts(engine.AddArtifactsRequest{
		Root: *workspace, Repository: flags.Arg(0), Artifacts: flags.Args()[1:], Track: *track,
	})
	if err != nil {
		return err
	}
	printBrand(stdout)
	fmt.Fprintf(stdout, "📦  locked %d %s in %s", result.Added, plural(result.Added, "artifact", "artifacts"), result.Repository)
	if result.Skipped != 0 {
		fmt.Fprintf(stdout, " (%d already present)", result.Skipped)
	}
	fmt.Fprintln(stdout)
	for _, packageVersion := range result.Packages {
		fmt.Fprintf(stdout, "✉️   %s\n", packageVersion)
	}
	return nil
}

func runPlan(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("plan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	workspace := flags.String("workspace", ".", "workspace root")
	output := flags.String("out", "snailmail.snailmail-plan.json", "plan output file")
	generatedAtValue := flags.String("generated-at", "", "explicit RFC3339 repository generation time")
	expires := flags.Duration("expires", 2*time.Hour, "plan lifetime")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	generatedAt, err := optionalTime(*generatedAtValue)
	if err != nil {
		return err
	}
	result, err := engine.PlanWorkspace(ctx, engine.PlanWorkspaceRequest{
		Root: *workspace, Output: *output, GeneratedAt: generatedAt, ExpiresIn: *expires,
	})
	if err != nil {
		return err
	}
	printBrand(stdout)
	fmt.Fprintf(stdout, "📦  planned %d repository %s\n", result.Changes, plural(result.Changes, "change", "changes"))
	fmt.Fprintf(stdout, "✉️   %s\n", result.Output)
	fmt.Fprintf(stdout, "    plan sha256:%s\n", result.PlanID)
	return nil
}

func runApply(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("apply", flag.ContinueOnError)
	flags.SetOutput(stderr)
	workspace := flags.String("workspace", ".", "workspace root")
	plan := flags.String("plan", "snailmail.snailmail-plan.json", "reviewed plan file")
	structuralOnly := flags.Bool("structural-only", false, "skip ecosystem client verification")
	python := flags.String("python", "python3", "Python executable for PyPI verification")
	runner := flags.String("runner", "podman", "OCI runner for Debian and Helm verification")
	debianImage := flags.String("debian-image", engine.DefaultDebianVerificationImage, "digest-pinned Debian image")
	helmImage := flags.String("helm-image", engine.DefaultHelmVerificationImage, "digest-pinned Helm image")
	maxWorkspaceMiB := flags.Int64("max-workspace-mib", 4096, "maximum Debian verification workspace in MiB")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	result, err := engine.ApplyWorkspace(ctx, engine.ApplyWorkspaceRequest{
		Root: *workspace, Plan: *plan, StructuralOnly: *structuralOnly, Python: *python, Runner: *runner,
		DebianImage: *debianImage, HelmImage: *helmImage, MaxWorkspaceBytes: *maxWorkspaceMiB << 20,
	})
	if err != nil {
		return err
	}
	printBrand(stdout)
	fmt.Fprintf(stdout, "📦  applied %d repository %s", result.Applied, plural(result.Applied, "change", "changes"))
	if result.Current != 0 {
		fmt.Fprintf(stdout, " (%d already current)", result.Current)
	}
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "✉️   plan sha256:%s\n", result.PlanID)
	return nil
}

func runBuild(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: snailmail build <pypi|deb|helm> [options]")
	}
	switch args[0] {
	case "pypi":
		return runBuildPyPI(ctx, args[1:], stdout, stderr)
	case "deb":
		return runBuildDeb(ctx, args[1:], stdout, stderr)
	case "helm":
		return runBuildHelm(ctx, args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown build format %q", args[0])
	}
}

func runBuildPyPI(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("build pypi", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("input", "", "directory containing wheels and source distributions")
	output := flags.String("output", "", "directory to write the static repository")
	generatedAtValue := flags.String("generated-at", defaultGeneratedAt, "explicit RFC3339 generation time")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	generatedAt, err := time.Parse(time.RFC3339, *generatedAtValue)
	if err != nil {
		return fmt.Errorf("parse --generated-at: %w", err)
	}
	result, err := engine.BuildPyPI(ctx, engine.BuildPyPIRequest{
		Input:       *input,
		Output:      *output,
		GeneratedAt: generatedAt,
	})
	if err != nil {
		return err
	}
	printBrand(stdout)
	fmt.Fprintf(stdout, "📦  packed %d %s across %d %s\n", result.DistributionCount, plural(result.DistributionCount, "distribution", "distributions"), result.ProjectCount, plural(result.ProjectCount, "project", "projects"))
	fmt.Fprintf(stdout, "✉️   wrote %s to %s\n", result.Format, result.Output)
	fmt.Fprintf(stdout, "    tree sha256:%s\n", result.TreeSHA256)
	return nil
}

func runBuildDeb(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("build deb", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("input", "", "directory containing Debian packages")
	output := flags.String("output", "", "directory to write the static repository")
	suite := flags.String("suite", "stable", "Debian suite/codename")
	component := flags.String("component", "main", "Debian component")
	architecturesValue := flags.String("architectures", "amd64", "comma-separated target architectures")
	generatedAtValue := flags.String("generated-at", defaultGeneratedAt, "explicit RFC3339 generation time")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	generatedAt, err := time.Parse(time.RFC3339, *generatedAtValue)
	if err != nil {
		return fmt.Errorf("parse --generated-at: %w", err)
	}
	result, err := engine.BuildDeb(ctx, engine.BuildDebRequest{
		Input:         *input,
		Output:        *output,
		Suite:         *suite,
		Component:     *component,
		Architectures: splitList(*architecturesValue),
		GeneratedAt:   generatedAt,
	})
	if err != nil {
		return err
	}
	printBrand(stdout)
	fmt.Fprintf(stdout, "📦  indexed %d %s across %d %s\n", result.DistributionCount, plural(result.DistributionCount, "package file", "package files"), result.PackageCount, plural(result.PackageCount, "package", "packages"))
	fmt.Fprintf(stdout, "✉️   wrote %s to %s\n", result.Format, result.Output)
	fmt.Fprintf(stdout, "    tree sha256:%s\n", result.TreeSHA256)
	return nil
}

func runBuildHelm(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("build helm", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("input", "", "directory containing packaged Helm charts")
	output := flags.String("output", "", "directory to write the static repository")
	generatedAtValue := flags.String("generated-at", defaultGeneratedAt, "explicit RFC3339 generation time")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	generatedAt, err := time.Parse(time.RFC3339, *generatedAtValue)
	if err != nil {
		return fmt.Errorf("parse --generated-at: %w", err)
	}
	result, err := engine.BuildHelm(ctx, engine.BuildHelmRequest{Input: *input, Output: *output, GeneratedAt: generatedAt})
	if err != nil {
		return err
	}
	printBrand(stdout)
	fmt.Fprintf(stdout, "📦  indexed %d %s across %d %s\n", result.DistributionCount, plural(result.DistributionCount, "chart archive", "chart archives"), result.PackageCount, plural(result.PackageCount, "chart", "charts"))
	fmt.Fprintf(stdout, "✉️   wrote %s to %s\n", result.Format, result.Output)
	fmt.Fprintf(stdout, "    tree sha256:%s\n", result.TreeSHA256)
	return nil
}

func runVerify(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: snailmail verify <pypi|deb|helm> [options]")
	}
	switch args[0] {
	case "pypi":
		return runVerifyPyPI(ctx, args[1:], stdout, stderr)
	case "deb":
		return runVerifyDeb(ctx, args[1:], stdout, stderr)
	case "helm":
		return runVerifyHelm(ctx, args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown verify format %q", args[0])
	}
}

func runVerifyPyPI(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("verify pypi", flag.ContinueOnError)
	flags.SetOutput(stderr)
	repository := flags.String("repo", "", "generated repository directory")
	python := flags.String("python", "python3", "Python executable whose pip client verifies installs")
	structuralOnly := flags.Bool("structural-only", false, "verify files and indexes without invoking pip")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	result, err := engine.VerifyPyPI(ctx, engine.VerifyPyPIRequest{
		Repository:     *repository,
		Python:         *python,
		StructuralOnly: *structuralOnly,
	})
	if err != nil {
		return err
	}
	printBrand(stdout)
	fmt.Fprintf(stdout, "📦  verified %d repository %s\n", result.FileCount, plural(result.FileCount, "file", "files"))
	if *structuralOnly {
		fmt.Fprintln(stdout, "✉️   structural verification passed")
	} else {
		fmt.Fprintf(stdout, "✉️   pip installed %d %s from the staged repository\n", result.InstalledCases, plural(result.InstalledCases, "package version", "package versions"))
	}
	fmt.Fprintf(stdout, "    tree sha256:%s\n", result.TreeSHA256)
	return nil
}

func runVerifyDeb(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("verify deb", flag.ContinueOnError)
	flags.SetOutput(stderr)
	repository := flags.String("repo", "", "generated repository directory")
	runner := flags.String("runner", "podman", "OCI runner executable")
	image := flags.String("image", engine.DefaultDebianVerificationImage, "digest-pinned Debian client image")
	maxWorkspaceMiB := flags.Int64("max-workspace-mib", 4096, "maximum temporary verification workspace in MiB")
	structuralOnly := flags.Bool("structural-only", false, "verify files and indexes without invoking apt")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	result, err := engine.VerifyDeb(ctx, engine.VerifyDebRequest{
		Repository:        *repository,
		Runner:            *runner,
		Image:             *image,
		MaxWorkspaceBytes: *maxWorkspaceMiB << 20,
		StructuralOnly:    *structuralOnly,
	})
	if err != nil {
		return err
	}
	printBrand(stdout)
	fmt.Fprintf(stdout, "📦  verified %d repository %s\n", result.FileCount, plural(result.FileCount, "file", "files"))
	if *structuralOnly {
		fmt.Fprintln(stdout, "✉️   structural verification passed")
	} else {
		fmt.Fprintf(stdout, "✉️   apt installed %d %s from the staged repository\n", result.InstalledCases, plural(result.InstalledCases, "package version", "package versions"))
	}
	fmt.Fprintf(stdout, "    tree sha256:%s\n", result.TreeSHA256)
	return nil
}

func runVerifyHelm(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("verify helm", flag.ContinueOnError)
	flags.SetOutput(stderr)
	repository := flags.String("repo", "", "generated repository directory")
	runner := flags.String("runner", "podman", "OCI runner executable")
	image := flags.String("image", engine.DefaultHelmVerificationImage, "digest-pinned Helm client image")
	structuralOnly := flags.Bool("structural-only", false, "verify files and index without invoking Helm")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	result, err := engine.VerifyHelm(ctx, engine.VerifyHelmRequest{Repository: *repository, Runner: *runner, Image: *image, StructuralOnly: *structuralOnly})
	if err != nil {
		return err
	}
	printBrand(stdout)
	fmt.Fprintf(stdout, "📦  verified %d repository %s\n", result.FileCount, plural(result.FileCount, "file", "files"))
	if *structuralOnly {
		fmt.Fprintln(stdout, "✉️   structural verification passed")
	} else {
		fmt.Fprintf(stdout, "✉️   Helm pulled, linted, and rendered %d %s\n", result.InstalledCases, plural(result.InstalledCases, "chart version", "chart versions"))
	}
	fmt.Fprintf(stdout, "    tree sha256:%s\n", result.TreeSHA256)
	return nil
}

func runServe(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	repository := flags.String("repo", "", "generated repository directory")
	listenAddress := flags.String("listen", "127.0.0.1:8080", "HTTP listen address")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	absolute, err := filepath.Abs(*repository)
	if err != nil {
		return fmt.Errorf("resolve repository: %w", err)
	}
	release, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return fmt.Errorf("resolve repository release: %w", err)
	}
	info, err := engine.InspectRepository(release)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *listenAddress, err)
	}
	defer listener.Close()

	server := &http.Server{
		Handler:           http.FileServer(http.Dir(release)),
		ReadHeaderTimeout: 5 * time.Second,
	}
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdownCtx)
		case <-stopped:
		}
	}()

	printBrand(stdout)
	fmt.Fprintf(stdout, "📦  checked %s repository with %d %s\n", info.Format, info.FileCount, plural(info.FileCount, "file", "files"))
	fmt.Fprintf(stdout, "✉️   serving %s at http://%s\n", absolute, listener.Addr())
	err = server.Serve(listener)
	close(stopped)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func printUsage(output io.Writer) {
	printBrand(output)
	fmt.Fprintln(output, "relaxed package delivery")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Usage:")
	fmt.Fprintln(output, "  snailmail init --name NAME")
	fmt.Fprintln(output, "  snailmail setup <pypi|deb|helm> --name NAME --output DIR")
	fmt.Fprintln(output, "  snailmail add REPOSITORY ARTIFACT...")
	fmt.Fprintln(output, "  snailmail plan [--out snailmail.snailmail-plan.json]")
	fmt.Fprintln(output, "  snailmail apply [--plan snailmail.snailmail-plan.json]")
	fmt.Fprintln(output, "  snailmail build pypi --input DIR --output DIR")
	fmt.Fprintln(output, "  snailmail build deb --input DIR --output DIR [--suite stable --architectures amd64]")
	fmt.Fprintln(output, "  snailmail build helm --input DIR --output DIR")
	fmt.Fprintln(output, "  snailmail verify pypi --repo DIR [--python python3]")
	fmt.Fprintln(output, "  snailmail verify deb --repo DIR [--runner podman]")
	fmt.Fprintln(output, "  snailmail verify helm --repo DIR [--runner podman]")
	fmt.Fprintln(output, "  snailmail serve --repo DIR [--listen 127.0.0.1:8080]")
}

func splitList(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}

func optionalTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse time: %w", err)
	}
	return parsed, nil
}

func printBrand(output io.Writer) {
	fmt.Fprintln(output, "🐌  snailmail")
}

func plural(count int, singular, pluralForm string) string {
	if count == 1 {
		return singular
	}
	return pluralForm
}
