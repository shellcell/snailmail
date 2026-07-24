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

func printBrand(output io.Writer) {
	fmt.Fprintln(output, "🐌  snailmail")
}

func plural(count int, singular, pluralForm string) string {
	if count == 1 {
		return singular
	}
	return pluralForm
}
