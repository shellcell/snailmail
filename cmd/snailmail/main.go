package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	httpsource "github.com/shellcell/snailmail/adapters/source/http"
	"github.com/shellcell/snailmail/engine"
	"github.com/shellcell/snailmail/gate"
	"github.com/shellcell/snailmail/internal/state"
	"github.com/shellcell/snailmail/internal/version"
	"github.com/shellcell/snailmail/internal/wire"
	"github.com/shellcell/snailmail/signer"
	"github.com/shellcell/snailmail/source"
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
	case "version", "--version", "-version":
		return runVersion(args[1:], stdout, stderr)
	case "init":
		return runInit(args[1:], stdout, stderr)
	case "setup":
		return runSetup(args[1:], stdout, stderr)
	case "add":
		return runAdd(ctx, args[1:], stdout, stderr)
	case "promote":
		return runPromote(args[1:], stdout, stderr)
	case "yank":
		return runYank(args[1:], stdout, stderr)
	case "prune":
		return runPrune(args[1:], stdout, stderr)
	case "check":
		return runCheck(ctx, args[1:], stdout, stderr)
	case "status":
		return runStatus(ctx, args[1:], stdout, stderr)
	case "site":
		return runSite(ctx, args[1:], stdout, stderr)
	case "rollout":
		return runRollout(ctx, args[1:], stdout, stderr)
	case "collect":
		return runCollect(ctx, args[1:], stdout, stderr)
	case "rollback":
		return runRollback(ctx, args[1:], stdout, stderr)
	case "import":
		return runImport(ctx, args[1:], stdout, stderr)
	case "ci":
		return runCI(ctx, args[1:], stdout, stderr)
	case "doctor":
		return runDoctor(ctx, args[1:], stdout, stderr)
	case "adopt":
		return runAdopt(ctx, args[1:], stdout, stderr)
	case "blob-store":
		return runBlobStore(ctx, args[1:], stdout, stderr)
	case "plan":
		return runPlan(ctx, args[1:], stdout, stderr)
	case "apply":
		return runApply(ctx, args[1:], stdout, stderr)
	case "approve":
		return runApprove(args[1:], stdout, stderr)
	case "approval-key":
		return runApprovalKey(args[1:], stdout, stderr)
	case "keys":
		return runKeys(ctx, args[1:], stdout, stderr)
	// "dashboard" says what it produces. "render" said nothing, and sat one letter
	// of meaning away from "site", which builds the browsable package listing that
	// clients install from — a different thing entirely. Kept as an alias because
	// someone's script may call it.
	case "dashboard", "render":
		return runRender(args[1:], stdout, stderr)
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
	flags := newCommandFlags("init", stderr).withWorkspace().withJSON()
	name := flags.String("name", "", "workspace name")
	forgeRepository := flags.String("forge-repo", "", "state repository reference for PR gates, such as owner/name")
	forgeProvider := flags.String("forge", "", "forge hosting the state repository: github, gitlab, forgejo, gitea, none")
	forgeHost := flags.String("forge-host", "", "self-hosted or Enterprise forge hostname")
	skipGit := flags.Bool("no-git", false,
		"do not create a Git repository here, for a workspace going inside one you will create yourself")
	if err := flags.parse(args); err != nil {
		return err
	}
	created, err := engine.InitWorkspaceReporting(engine.InitWorkspaceRequest{Root: flags.Root(), Name: *name,
		SkipGit: *skipGit, Forge: *forgeProvider, ForgeRepository: *forgeRepository, ForgeHost: *forgeHost})
	if err != nil {
		return err
	}
	if done, err := flags.emit(stdout, initResult{
		Workspace: *name, CreatedGitRepository: created.CreatedGitRepository, Committed: created.Committed,
	}); done || err != nil {
		return err
	}
	printBrand(stdout)
	// Said rather than done silently: this wrote to the operator's directory beyond
	// the files they asked for.
	if created.CreatedGitRepository {
		fmt.Fprintln(stdout, "📦  created a Git repository here, because snailmail reviews its state as a diff")
	}
	if created.Committed {
		fmt.Fprintln(stdout, "📦  committed the new workspace, so it is ready to use")
	}
	// The workspace is written and correct; git simply cannot say who made the
	// commit. Naming both commands, because someone who has never configured git is
	// exactly the person who will not know the second one either.
	if created.CommitPending {
		fmt.Fprintln(stderr, "⚠️   the workspace was created but not committed: Git has no configured identity")
		fmt.Fprintln(stderr, "     git config --global user.name \"Your Name\"")
		fmt.Fprintln(stderr, "     git config --global user.email \"you@example.com\"")
		fmt.Fprintln(stderr, "     git -C . add -A && git -C . commit -m \"snailmail workspace\"")
	}
	fmt.Fprintf(stdout, "✉️   initialized workspace %s\n", *name)
	suggestNext(stdout, flags, "snailmail setup raw --name tools --output public/tools",
		"configure a repository")
	return nil
}

func runSetup(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: snailmail setup <pypi|deb|helm|raw|rpm|apk> --name NAME --host <local|s3|github-pages> [host options]")
	}
	format := args[0]
	flags := newCommandFlags("setup "+format, stderr).withWorkspace().withJSON()
	name := flags.String("name", "", "repository name")
	output := flags.String("output", "",
		"published directory: workspace-relative for a local host, an absolute remote path for rsync")
	hostType := flags.String("host", "local", "host type: local, s3, or github-pages")
	visibility := flags.String("visibility", "public", "repository visibility")
	gatePolicy := flags.String("gate", "auto", "publication gate: auto, pr, or approval")
	approvalKeys := flags.String("approval-keys", "", "comma-separated allowed Ed25519 public keys")
	signingKey := flags.String("signing-key", "", "repository signing key name")
	allowUnsigned := flags.Bool("allow-unsigned", false, "explicitly allow a new unsigned Debian repository")
	track := flags.String("track", "stable", "rendered placement track")
	keep := flags.Int("keep", 0,
		"publications to retain when collecting; 0 uses the default and can be changed later in snailmail.toml")
	sshTarget := flags.String("target", "", "ssh destination for an rsync host, such as deploy@packages.example")
	bucket := flags.String("bucket", "", "S3 bucket")
	prefix := flags.String("prefix", "", "S3 object prefix")
	region := flags.String("region", "", "AWS region")
	endpoint := flags.String("endpoint", "", "optional S3 API endpoint")
	canonicalEndpoint := flags.String("base-url", "", "canonical public repository URL")
	usePathStyle := flags.Bool("use-path-style", false, "use path-style S3 requests")
	readAuth := flags.String("read-auth", "", "private read authentication: basic")
	credentialBroker := flags.String("credential-broker", "", "non-secret credential broker reference")
	githubRepository := flags.String("github-repo", "", "GitHub Pages repository (owner/name)")
	githubBranch := flags.String("branch", "", "GitHub Pages publish branch")
	githubPreviewRepository := flags.String("github-preview-repo", "", "companion preview Pages repository (owner/name)")
	githubPreviewBranch := flags.String("preview-branch", "", "preview Pages publish branch")
	githubPreviewEndpoint := flags.String("preview-url", "", "companion preview Pages base URL")
	suite := flags.String("suite", "stable", "Debian suite")
	component := flags.String("component", "main", "Debian component")
	defaultArchitectures := "amd64"
	if format == "apk" {
		// Alpine names the same machine x86_64, and an index under the wrong
		// name is one no client looks for.
		defaultArchitectures = "x86_64"
	}
	architectures := flags.String("architectures", defaultArchitectures, "comma-separated architectures the repository serves")
	if err := flags.parse(args[1:]); err != nil {
		return err
	}
	resolvedApprovalKeys := splitList(*approvalKeys)
	sort.Strings(resolvedApprovalKeys)
	if err := engine.SetupRepository(engine.SetupRepositoryRequest{
		Root: flags.Root(), Name: *name, Format: format, Output: *output,
		HostType: *hostType, Visibility: *visibility, Gate: *gatePolicy, ApprovalKeys: resolvedApprovalKeys, SigningKey: *signingKey, AllowUnsigned: *allowUnsigned, Bucket: *bucket, Prefix: *prefix,
		Target: *sshTarget, Keep: *keep,
		Region: *region, Endpoint: *endpoint, CanonicalEndpoint: *canonicalEndpoint,
		UsePathStyle: *usePathStyle,
		ReadAuth:     *readAuth, CredentialBroker: *credentialBroker,
		RemoteRepository: *githubRepository, Branch: *githubBranch, PreviewRepository: *githubPreviewRepository,
		PreviewBranch: *githubPreviewBranch, PreviewEndpoint: *githubPreviewEndpoint,
		Track: *track, Suite: *suite, Component: *component, Architectures: splitList(*architectures),
	}); err != nil {
		return err
	}
	target := *output
	if *hostType == "s3" || *hostType == "github-pages" {
		target = *canonicalEndpoint
	}
	if done, err := flags.emit(stdout, setupResult{Repository: *name, Format: format, Target: target}); done || err != nil {
		return err
	}
	printBrand(stdout)
	fmt.Fprintf(stdout, "📦  configured %s repository %s\n", format, *name)
	fmt.Fprintf(stdout, "✉️   desired state will publish to %s\n", target)
	suggestNext(stdout, flags, "snailmail add "+*name+" ./path/to/artifact",
		"record an artifact")
	return nil
}

func runKeys(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: snailmail keys <new|publish|attach|rotate|audit> [options]")
	}
	switch args[0] {
	case "new":
		if len(args) < 2 {
			return errors.New("usage: snailmail keys new NAME [--algo openpgp-rsa4096] [--expires-in 17520h]")
		}
		name := args[1]
		flags := newCommandFlags("keys new", stderr).withWorkspace().withJSON()
		algorithm := flags.String("algo", "openpgp-rsa4096", "signing algorithm")
		expiresIn := flags.Duration("expires-in", 2*365*24*time.Hour, "key validity duration")
		if err := flags.parse(args[2:]); err != nil {
			return err
		}
		store, err := wire.NewSignerStore()
		if err != nil {
			return err
		}
		result, err := engine.NewKey(ctx, engine.NewKeyRequest{Root: flags.Root(), Name: name, Algorithm: *algorithm, ExpiresIn: *expiresIn, Keys: store})
		if err != nil {
			return err
		}
		if done, err := flags.emit(stdout, result); done || err != nil {
			return err
		}
		printBrand(stdout)
		fmt.Fprintf(stdout, "📦  generated signing key %s\n", result.Name)
		fmt.Fprintf(stdout, "✉️   fingerprint %s; expires %s\n", result.Fingerprint, result.ExpiresAt)
		fmt.Fprintf(stdout, "    key reference %s\n", result.Reference)
		return nil
	case "attach":
		if len(args) < 2 {
			return errors.New("usage: snailmail keys attach REPOSITORY --key NAME")
		}
		repository := args[1]
		flags := newCommandFlags("keys attach", stderr).withWorkspace().withJSON()
		key := flags.String("key", "", "signing key name to attach")
		if err := flags.parse(args[2:]); err != nil {
			return err
		}
		result, err := engine.AttachKey(engine.AttachKeyRequest{Root: flags.Root(), Repository: repository, Key: *key})
		if err != nil {
			return err
		}
		if done, err := flags.emit(stdout, result); done || err != nil {
			return err
		}
		printBrand(stdout)
		fmt.Fprintf(stdout, "📦  %s is now signed by %s\n", result.Repository, result.Key)
		fmt.Fprintf(stdout, "✉️   fingerprint %s\n", result.Fingerprint)
		fmt.Fprintf(stdout, "    clients install %s\n", result.Keyring)
		return nil
	case "publish":
		if len(args) < 2 {
			return errors.New("usage: snailmail keys publish NAME")
		}
		name := args[1]
		flags := newCommandFlags("keys publish", stderr).withWorkspace().withJSON()
		if err := flags.parse(args[2:]); err != nil {
			return err
		}
		store, err := wire.NewSignerStore()
		if err != nil {
			return err
		}
		result, err := engine.PublishKey(ctx, engine.PublishKeyRequest{Root: flags.Root(), Name: name, Keys: store})
		if err != nil {
			return err
		}
		if done, err := flags.emit(stdout, publishKeyResult{Name: result.Name, Fingerprint: result.Fingerprint}); done || err != nil {
			return err
		}
		printBrand(stdout)
		fmt.Fprintf(stdout, "📦  published public forms for %s\n", result.Name)
		fmt.Fprintf(stdout, "✉️   fingerprint %s\n", result.Fingerprint)
		return nil
	case "rotate":
		if len(args) < 2 {
			return errors.New("usage: snailmail keys rotate REPOSITORY --successor KEY [--minimum-refresh 720h] | --advance --yes")
		}
		repository := args[1]
		flags := newCommandFlags("keys rotate", stderr).withWorkspace().withJSON()
		successor := flags.String("successor", "", "successor signing key name")
		advance := flags.Bool("advance", false, "advance the deployed rotation to its next phase")
		minimumRefresh := flags.Duration("minimum-refresh", 30*24*time.Hour, "minimum client keyring refresh window")
		expiresIn := flags.Duration("expires-in", 2*365*24*time.Hour, "new successor key validity")
		confirmed := flags.Bool("yes", false, "confirm an advance transition")
		if err := flags.parse(args[2:]); err != nil {
			return err
		}
		if *advance && !*confirmed {
			return errors.New("keys rotate --advance requires --yes")
		}
		if !*advance && *successor == "" {
			return errors.New("keys rotate requires --successor when starting a rotation")
		}
		var keyGenerator signer.Generator
		var err error
		if !*advance {
			keyGenerator, err = wire.NewSignerStore()
			if err != nil {
				return err
			}
		}
		result, err := engine.RotateKey(ctx, engine.RotateKeyRequest{
			Root: flags.Root(), Repository: repository, Successor: *successor, Advance: *advance,
			MinimumRefresh: *minimumRefresh, ExpiresIn: *expiresIn, Keys: keyGenerator,
		})
		if err != nil {
			return err
		}
		if done, err := flags.emit(stdout, result); done || err != nil {
			return err
		}
		printBrand(stdout)
		fmt.Fprintf(stdout, "📦  signing rotation for %s is %s\n", result.Repository, result.Phase)
		fmt.Fprintf(stdout, "✉️   active %s; trusted %s\n", result.ActiveKey, strings.Join(result.TrustedKeys, ", "))
		if result.EarliestAdvance != "" {
			fmt.Fprintf(stdout, "    earliest next transition %s\n", result.EarliestAdvance)
		}
		if result.RequiresDeploy {
			fmt.Fprintln(stdout, "    commit this state, then run plan and apply")
		}
		return nil
	case "audit":
		flags := newCommandFlags("keys audit", stderr).withWorkspace().withJSON()
		if err := flags.parse(args[1:]); err != nil {
			return err
		}
		result, err := engine.AuditKeys(engine.PublishKeyRequest{Root: flags.Root()}, time.Time{})
		if err != nil {
			return err
		}
		if done, emitErr := flags.emit(stdout, result); done || emitErr != nil {
			if emitErr != nil {
				return emitErr
			}
			// The audit's exit status is part of its contract, so JSON output
			// still fails when the audit found errors.
			for _, finding := range result.Findings {
				if finding.Severity == "error" {
					return errors.New("signing key audit found errors")
				}
			}
			return nil
		}
		printBrand(stdout)
		if len(result.Findings) == 0 {
			fmt.Fprintln(stdout, "📦  signing keys and repository compatibility are valid")
		}
		for _, rotation := range result.Rotations {
			state := "awaiting deployment"
			if rotation.Deployed && rotation.Ready {
				state = "ready to advance"
			} else if rotation.Deployed {
				state = "waiting until " + rotation.EarliestAdvance
			}
			fmt.Fprintf(stdout, "📦  rotation %s is %s: %s\n", rotation.Repository, rotation.Phase, state)
		}
		hasErrors := false
		for _, finding := range result.Findings {
			fmt.Fprintf(stdout, "✉️   %s %s: %s\n", finding.Severity, finding.Subject, finding.Message)
			hasErrors = hasErrors || finding.Severity == "error"
		}
		if hasErrors {
			return errors.New("signing key audit found errors")
		}
		return nil
	default:
		return fmt.Errorf("unknown keys command %q", args[0])
	}
}

func runAdd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := newCommandFlags("add", stderr).withWorkspace().withJSON()
	track := flags.String("track", "stable", "placement track")
	name := flags.String("name", "", "package name, for formats whose artifacts carry none")
	version := flags.String("version", "", "package version, for formats whose artifacts carry none")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() < 2 {
		return errors.New("usage: snailmail add [--track stable] REPOSITORY ARTIFACT...")
	}
	result, err := engine.AddArtifacts(engine.AddArtifactsRequest{
		Context: ctx, Root: flags.Root(), Repository: flags.Arg(0), Artifacts: flags.Args()[1:], Track: *track,
		Name: *name, Version: *version, Blobs: wire.NewBlobResolver(),
	})
	if err != nil {
		return err
	}
	if done, err := flags.emit(stdout, result); done || err != nil {
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
	// Commit first, and say why: plan refuses an uncommitted workspace, which is the
	// first refusal most people meet and reads as a bug until the reason is clear.
	// Desired state is reviewed as a diff, so it has to be committed to be reviewed.
	suggestNext(stdout, flags, "git commit -am \"add artifacts\" && snailmail plan",
		"plan reads committed state, because desired state is reviewed as a diff")
	return nil
}

func runPromote(args []string, stdout, stderr io.Writer) error {
	flags := newCommandFlags("promote", stderr).withWorkspace().withJSON()
	track := flags.String("track", "stable", "destination placement track")
	distro := flags.String("distro", "", "Debian placement distro (defaults to repository suite)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 3 {
		return errors.New("usage: snailmail promote [--track stable] [--distro DISTRO] REPOSITORY PACKAGE VERSION")
	}
	result, err := engine.Promote(engine.PlacementMutationRequest{
		Root: flags.Root(), Repository: flags.Arg(0), Package: flags.Arg(1), Version: flags.Arg(2), Track: *track, Distro: *distro,
	})
	if err != nil {
		return err
	}
	if done, err := flags.emit(stdout, result); done || err != nil {
		return err
	}
	printBrand(stdout)
	if result.Changed == 0 {
		fmt.Fprintf(stdout, "📦  placement %s@%s is already present in %s/%s\n", result.Package, result.Version, result.Repository, result.Track)
	} else {
		fmt.Fprintf(stdout, "📦  placed %s@%s in %s/%s\n", result.Package, result.Version, result.Repository, result.Track)
	}
	return nil
}

func runYank(args []string, stdout, stderr io.Writer) error {
	flags := newCommandFlags("yank", stderr).withWorkspace().withJSON()
	track := flags.String("track", "", "placement track to remove")
	distro := flags.String("distro", "", "Debian placement distro (defaults to repository suite)")
	all := flags.Bool("all", false, "remove every placement for the package version")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 3 || (*all == (*track != "")) || (*all && *distro != "") {
		return errors.New("usage: snailmail yank (--track TRACK [--distro DISTRO] | --all) REPOSITORY PACKAGE VERSION")
	}
	result, err := engine.Yank(engine.PlacementMutationRequest{
		Root: flags.Root(), Repository: flags.Arg(0), Package: flags.Arg(1), Version: flags.Arg(2), Track: *track, Distro: *distro, All: *all,
	})
	if err != nil {
		return err
	}
	if done, err := flags.emit(stdout, result); done || err != nil {
		return err
	}
	printBrand(stdout)
	if result.All {
		fmt.Fprintf(stdout, "📦  removed %d %s for %s@%s from %s\n", result.Changed, plural(result.Changed, "placement", "placements"), result.Package, result.Version, result.Repository)
	} else if result.Changed == 0 {
		fmt.Fprintf(stdout, "📦  placement %s@%s is already absent from %s/%s\n", result.Package, result.Version, result.Repository, result.Track)
	} else {
		fmt.Fprintf(stdout, "📦  removed %s@%s from %s/%s\n", result.Package, result.Version, result.Repository, result.Track)
	}
	return nil
}

func runPrune(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: snailmail prune REPOSITORY --keep N")
	}
	repository := args[0]
	flags := newCommandFlags("prune", stderr).withWorkspace().withJSON()
	keep := flags.Int("keep", 0, "versions to retain per package, track, and distro")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *keep < 1 {
		return errors.New("usage: snailmail prune REPOSITORY --keep N")
	}
	result, err := engine.Prune(engine.PruneRequest{Root: flags.Root(), Repository: repository, Keep: *keep})
	if err != nil {
		return err
	}
	if done, err := flags.emit(stdout, result); done || err != nil {
		return err
	}
	printBrand(stdout)
	if result.Removed == 0 {
		fmt.Fprintf(stdout, "📦  %s already retains at most %d %s per placement view\n", result.Repository, result.Keep, plural(result.Keep, "version", "versions"))
	} else {
		fmt.Fprintf(stdout, "📦  removed %d old %s from %s placements\n", result.Removed, plural(result.Removed, "placement", "placements"), result.Repository)
	}
	fmt.Fprintln(stdout, "✉️   package versions and blobs were retained")
	return nil
}

func runCheck(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := newCommandFlags("check", stderr).withWorkspace().withJSON()
	origins := flags.Bool("origins", false, "re-fetch recorded adopted origins")
	maxOrigins := flags.Int("max-origins", 2, "maximum recorded origins to re-fetch (1-4)")
	originOffset := flags.Int("origin-offset", 0, "skip this many sorted recorded origins")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: snailmail check [--workspace DIR] [--json] [--origins --max-origins N --origin-offset N]")
	}
	result, err := engine.CheckWorkspace(ctx, engine.CheckWorkspaceRequest{Root: flags.Root(), Blobs: wire.NewBlobResolver(), Origins: *origins, Sources: httpsource.New(), MaxOrigins: *maxOrigins, OriginOffset: *originOffset})
	if err != nil {
		return err
	}
	if done, emitErr := flags.emit(stdout, result); done || emitErr != nil {
		if emitErr != nil {
			return emitErr
		}
		// The exit status is part of check's contract, so JSON output still
		// fails when an artifact is unavailable or changed.
		if len(result.Findings) != 0 {
			return fmt.Errorf("check found %d unavailable or changed %s", len(result.Findings), plural(len(result.Findings), "artifact", "artifacts"))
		}
		return nil
	}
	printBrand(stdout)
	fmt.Fprintf(stdout, "📦  checked %d %s, %d package versions, and %d locked %s\n",
		result.Repositories, plural(result.Repositories, "repository", "repositories"), result.PackageVersions, result.Artifacts, plural(result.Artifacts, "artifact", "artifacts"))
	for _, finding := range result.Findings {
		fmt.Fprintf(stdout, "✉️   [%s] %s: %s\n", finding.State, finding.Subject, finding.Message)
	}
	if *origins {
		fmt.Fprintf(stdout, "✉️   checked %d recorded origins and skipped %d beyond the limit; artifacts without origins remain unavailable for source comparison\n", result.OriginsChecked, result.OriginsSkipped)
	} else {
		fmt.Fprintln(stdout, "✉️   adopted-origin checks disabled; use --origins to re-fetch recorded pins")
	}
	if len(result.Findings) != 0 {
		return fmt.Errorf("check found %d unavailable or changed %s", len(result.Findings), plural(len(result.Findings), "artifact", "artifacts"))
	}
	return nil
}

func runSite(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := newCommandFlags("site", stderr).withWorkspace()
	title := flags.String("title", "", "page title (defaults to the workspace name)")
	description := flags.String("description", "", "one line shown under the title")
	output := flags.String("output", "", "where to write the page (defaults to the directory the repositories share)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: snailmail site [--workspace DIR] [--title TITLE] [--description TEXT] [--output PATH]")
	}
	result, err := engine.SiteIndex(ctx, engine.SiteIndexRequest{
		Root: flags.Root(), Title: *title, Description: *description, Output: *output,
	})
	if err != nil {
		return err
	}
	printBrand(stdout)
	fmt.Fprintf(stdout, "📦  wrote %s: %d packages across %d repositories\n",
		result.Path, result.Packages, result.Repositories)
	return nil
}

func runCI(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: snailmail ci <github|gitlab> [--workspace DIR] [--snailmail-version vX.Y.Z]")
	}
	provider := args[0]
	flags := newCommandFlags("ci "+provider, stderr).withWorkspace()
	version := flags.String("snailmail-version", "", "snailmail release the workflow installs")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: snailmail ci <github|gitlab> [--workspace DIR] [--snailmail-version vX.Y.Z]")
	}
	// To stdout, so the operator redirects it, reviews it, and owns it. A file
	// this wrote would be a file it would later overwrite. Which file it belongs
	// in differs per provider, which is another reason not to guess: .github/
	// workflows/publish.yml for Actions, .gitlab-ci.yml at the root for GitLab.
	workflow, err := engine.CIWorkflow(engine.CIWorkflowRequest{
		Root: flags.Root(), Version: *version, Provider: provider,
	})
	if err != nil {
		return err
	}
	_, err = stdout.Write(workflow)
	return err
}

func runRollout(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := newCommandFlags("rollout", stderr).withWorkspace().withJSON()
	repository := flags.String("repo", "", "report one repository")
	pkg := flags.String("package", "", "report one package")
	withdrawn := flags.Bool("withdrawn", false, "include versions no longer served")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: snailmail rollout [--workspace DIR] [--repo NAME] [--package NAME] [--withdrawn] [--json]")
	}
	result, err := engine.RolloutWorkspace(ctx, engine.RolloutWorkspaceRequest{
		Root: flags.Root(), Repository: *repository, Package: *pkg, IncludeWithdrawn: *withdrawn,
	})
	if err != nil {
		return err
	}
	if done, err := flags.emit(stdout, result); done || err != nil {
		return err
	}
	printBrand(stdout)
	fmt.Fprintf(stdout, "📦  workspace %s at %s\n", result.Workspace, result.GitRevision)
	for _, release := range result.Releases {
		note := fmt.Sprintf(", in %d published %s", release.Publications,
			plural(release.Publications, "tree", "trees"))
		if !release.Served {
			note += ", no longer served"
		}
		fmt.Fprintf(stdout, "✉️   %s: %s@%s first published %s%s\n",
			release.Repository, release.Package, release.Version, release.PublishedAt, note)
	}
	if len(result.Releases) == 0 {
		fmt.Fprintln(stdout, "✉️   nothing has been published from this workspace")
	}
	return nil
}

func runStatus(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := newCommandFlags("status", stderr).withWorkspace()
	jsonOutput := flags.Bool("json", false, "emit machine-readable JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: snailmail status [--workspace DIR] [--json]")
	}
	result, err := engine.StatusWorkspace(ctx, engine.StatusWorkspaceRequest{Root: flags.Root()})
	if err != nil {
		return err
	}
	if *jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}
	printBrand(stdout)
	fmt.Fprintf(stdout, "📦  workspace %s at %s\n", result.Workspace, result.GitRevision)
	for _, repository := range result.Repositories {
		fmt.Fprintf(stdout, "✉️   %s: %d visible, %d retained; visible bindings %s; deployment %s\n",
			repository.Name, repository.VisiblePackageVersions, repository.RetainedPackageVersions, repository.VisibleBindingState, repository.Deployment.State)
	}
	// The lock is what every plan and apply parses whole, so its size is the
	// number that predicts where a workspace stops being comfortable. Reported for
	// the workspace rather than per repository, with the largest named, because
	// that is the pair an operator can act on.
	if result.LockBytes != 0 {
		fmt.Fprintf(stdout, "📦  %s of lock across %d %s%s\n",
			humanBytes(result.LockBytes), len(result.Repositories),
			plural(len(result.Repositories), "repository", "repositories"), largestLockSuffix(result))
	}
	fmt.Fprintln(stdout, "✉️   live hosts, upstream releases, foreign remotes, gate completion, and apply failures were not observed")
	return nil
}

func runDoctor(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	return runDoctorWithFetcher(ctx, args, stdout, stderr, httpsource.New())
}

func runDoctorWithFetcher(ctx context.Context, args []string, stdout, stderr io.Writer, fetcher source.Fetcher) error {
	flags := newCommandFlags("doctor", stderr)
	format := flags.String("format", "auto", "repository format: auto, pypi, deb, or helm")
	project := flags.String("project", "", "PyPI project to inspect")
	suite := flags.String("suite", "", "Debian suite")
	component := flags.String("component", "", "Debian component")
	architecture := flags.String("architecture", "", "Debian architecture")
	maximum := flags.Int("max-artifacts", 4, "maximum referenced artifacts to inspect (1-4)")
	jsonOutput := flags.Bool("json", false, "emit machine-readable JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: snailmail doctor [options] URL")
	}
	result, err := engine.Doctor(ctx, engine.DoctorRequest{
		URL: flags.Arg(0), Format: *format, Project: *project, Suite: *suite, Component: *component,
		Architecture: *architecture, MaxArtifacts: *maximum, Fetcher: fetcher,
	})
	if err != nil {
		return err
	}
	if *jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			return err
		}
	} else {
		printBrand(stdout)
		fmt.Fprintf(stdout, "📦  inspected %s repository index with %d entries and %d referenced artifacts\n", result.Format, result.Entries, result.ArtifactsChecked)
		for _, finding := range result.Findings {
			fmt.Fprintf(stdout, "✉️   [%s] %s %s: %s\n", finding.Severity, finding.Code, finding.Subject, finding.Message)
		}
	}
	errorsFound := 0
	for _, finding := range result.Findings {
		if finding.Severity == "error" {
			errorsFound++
		}
	}
	if errorsFound != 0 {
		return fmt.Errorf("doctor found %d repository %s", errorsFound, plural(errorsFound, "error", "errors"))
	}
	return nil
}

func runAdopt(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	return runAdoptWithFetcher(ctx, args, stdout, stderr, httpsource.New())
}

func runAdoptWithFetcher(ctx context.Context, args []string, stdout, stderr io.Writer, fetcher source.Fetcher) error {
	flags := newCommandFlags("adopt", stderr).withWorkspace()
	digest := flags.String("sha256", "", "required artifact SHA-256 pin")
	filename := flags.String("filename", "", "artifact filename override")
	name := flags.String("name", "", "package name, for formats whose artifacts carry none")
	version := flags.String("version", "", "package version, for formats whose artifacts carry none")
	track := flags.String("track", "", "placement track")
	distro := flags.String("distro", "", "Debian placement distribution")
	dryRun := flags.Bool("dry-run", false, "validate without changing CAS or lock")
	publicOrigin := flags.Bool("public-origin", false, "confirm URL is public, non-secret, and will be committed")
	jsonOutput := flags.Bool("json", false, "emit machine-readable JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 2 || *digest == "" || !*publicOrigin {
		return errors.New("usage: snailmail adopt --sha256 HEX --public-origin [options] REPOSITORY URL")
	}
	result, err := engine.AdoptArtifact(ctx, engine.AdoptArtifactRequest{
		Root: flags.Root(), Repository: flags.Arg(0), URL: flags.Arg(1), SHA256: *digest,
		Filename: *filename, Name: *name, Version: *version, Track: *track, Distro: *distro, DryRun: *dryRun, PublicOrigin: *publicOrigin, Fetcher: fetcher,
	})
	if err != nil {
		return err
	}
	if *jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}
	printBrand(stdout)
	action := "already recorded"
	if result.Changed && result.DryRun {
		action = "would record"
	} else if result.Changed {
		action = "recorded"
	}
	fmt.Fprintf(stdout, "📦  %s %s@%s from pinned selected bytes\n", action, result.Package, result.Version)
	fmt.Fprintf(stdout, "✉️   sha256:%s %s\n", result.SHA256, result.OriginURL)
	return nil
}

func runBlobStore(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: snailmail blob-store <local|s3> [options]")
	}
	storeType := args[0]
	flags := newCommandFlags("blob-store "+storeType, stderr).withWorkspace().withJSON()
	bucket := flags.String("bucket", "", "S3 blob bucket")
	prefix := flags.String("prefix", "", "S3 blob prefix")
	region := flags.String("region", "", "AWS region")
	endpoint := flags.String("endpoint", "", "optional S3 API endpoint")
	usePathStyle := flags.Bool("use-path-style", false, "use path-style S3 requests")
	if err := flags.parse(args[1:]); err != nil {
		return err
	}
	if err := engine.ConfigureBlobStore(ctx, engine.ConfigureBlobStoreRequest{
		Root: flags.Root(), Type: storeType, Bucket: *bucket, Prefix: *prefix, Region: *region,
		Endpoint: *endpoint, UsePathStyle: *usePathStyle, Blobs: wire.NewBlobResolver(),
	}); err != nil {
		return err
	}
	if done, err := flags.emit(stdout, blobStoreResult{Type: storeType}); done || err != nil {
		return err
	}
	printBrand(stdout)
	fmt.Fprintf(stdout, "📦  configured %s blob storage\n", storeType)
	fmt.Fprintln(stdout, "✉️   existing locked artifacts are durable")
	return nil
}

func runPlan(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := newCommandFlags("plan", stderr).withWorkspace().withJSON()
	output := flags.String("out", defaultPlanFile, "plan output file")
	generatedAtValue := flags.String("generated-at", "", "explicit RFC3339 repository generation time")
	expires := flags.Duration("expires", 2*time.Hour, "plan lifetime")
	structuralOnly := flags.Bool("structural-only", false, "review a plan without ecosystem client verification")
	if err := flags.parse(args); err != nil {
		return err
	}
	generatedAt, err := optionalTime(*generatedAtValue)
	if err != nil {
		return err
	}
	hosts := wire.NewHostResolver()
	defer hosts.Close()
	signers, err := wire.NewSignerStore()
	if err != nil {
		return err
	}
	result, err := engine.PlanWorkspace(ctx, engine.PlanWorkspaceRequest{
		Root: flags.Root(), Output: *output, GeneratedAt: generatedAt, ExpiresIn: *expires,
		Hosts: hosts, Blobs: wire.NewBlobResolver(), Signers: signers, VerificationMode: verificationMode(*structuralOnly),
		Sources: httpsource.New(),
	})
	if err != nil {
		return err
	}
	if done, err := flags.emit(stdout, result); done || err != nil {
		return err
	}
	printBrand(stdout)
	fmt.Fprintf(stdout, "📦  planned %d repository %s\n", result.Changes, plural(result.Changes, "change", "changes"))
	fmt.Fprintf(stdout, "✉️   %s\n", result.Output)
	fmt.Fprintf(stdout, "    plan sha256:%s\n", result.PlanID)
	if result.Changes != 0 {
		// apply defaults to the same file plan defaults to, so the common case needs
		// no flag. Naming the absolute path when it is the default would be a long
		// line telling someone to type what they would get for free.
		next := "snailmail apply"
		if filepath.Base(result.Output) != defaultPlanFile {
			next += " --plan " + result.Output
		}
		suggestNext(stdout, flags, next, "publish it")
	}
	for _, acquisition := range result.Acquisitions {
		fmt.Fprintf(stdout, "✉️   adopted %s/%s@%s %s sha256:%s\n",
			acquisition.Repository, acquisition.Package, acquisition.Version, acquisition.OriginURL, acquisition.SHA256)
	}
	return nil
}

func runApply(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := newCommandFlags("apply", stderr).withWorkspace().withJSON()
	plan := flags.String("plan", defaultPlanFile, "reviewed plan file")
	structuralOnly := flags.Bool("structural-only", false, "skip ecosystem client verification")
	dryRun := flags.Bool("dry-run", false, "build, verify and check gates, then stop before writing to any host")
	python := flags.String("python", "python3", "Python executable for PyPI verification")
	runner := flags.String("runner", "podman", "OCI runner for Debian and Helm verification")
	debianImage := flags.String("debian-image", engine.DefaultDebianVerificationImage, "digest-pinned Debian image")
	helmImage := flags.String("helm-image", engine.DefaultHelmVerificationImage, "digest-pinned Helm image")
	// Every format that verifies through a container takes an override, so a
	// workspace can point at a mirror or an authenticated pull-through cache.
	// Without one, a repository is only publishable from a network that can
	// reach Docker Hub anonymously, and an exhausted quota there is reported as
	// an unresolvable image rather than as the quota it is.
	rpmImage := flags.String("rpm-image", engine.DefaultRPMVerificationImage, "digest-pinned RPM image")
	apkImage := flags.String("apk-image", engine.DefaultAPKVerificationImage, "digest-pinned Alpine image")
	imageRegistry := flags.String("image-registry", "", "fetch every verification image from this registry instead")
	verifyAllVersions := flags.Bool("verify-all-versions", false, "install every retained version with a client, not the newest and oldest of each")
	maxWorkspaceMiB := flags.Int64("max-workspace-mib", 4096, "maximum Debian verification workspace in MiB")
	approvalFile := flags.String("approvals", "", "approval evidence file (defaults beside plan)")
	if err := flags.parse(args); err != nil {
		return err
	}
	// Applied to every image, including any given explicitly: a workspace
	// choosing a mirror means all of them, and one format still reaching for
	// Docker Hub would keep the failure it was meant to avoid.
	for _, image := range []*string{debianImage, helmImage, rpmImage, apkImage} {
		moved, err := engine.ImageWithRegistry(*image, *imageRegistry)
		if err != nil {
			return err
		}
		*image = moved
	}
	hosts := wire.NewHostResolver()
	defer hosts.Close()
	resolvedApprovalFile := *approvalFile
	if resolvedApprovalFile == "" {
		resolvedApprovalFile = *plan + ".approvals.json"
	}
	if !filepath.IsAbs(resolvedApprovalFile) {
		resolvedApprovalFile = filepath.Join(flags.Root(), resolvedApprovalFile)
	}
	result, err := engine.ApplyWorkspace(ctx, engine.ApplyWorkspaceRequest{
		Progress: applyProgress(stderr, flags.jsonRequested()),
		Root:     flags.Root(), Plan: *plan, StructuralOnly: *structuralOnly, DryRun: *dryRun,
		Python: *python, Runner: *runner,
		DebianImage: *debianImage, HelmImage: *helmImage,
		RPMImage: *rpmImage, APKImage: *apkImage, VerifyAllVersions: *verifyAllVersions,
		MaxWorkspaceBytes: *maxWorkspaceMiB << 20,
		Hosts:             hosts, Blobs: wire.NewBlobResolver(), Gates: gate.NewDefaultEvaluator(resolvedApprovalFile, wire.NewForgeResolver()),
		Sources: httpsource.New(),
	})
	if err != nil {
		if result.Applied != 0 || result.Current != 0 {
			printBrand(stderr)
			fmt.Fprintf(stderr, "📦  applied %d repository %s before failure", result.Applied, plural(result.Applied, "change", "changes"))
			if result.Current != 0 {
				fmt.Fprintf(stderr, " (%d already current)", result.Current)
			}
			fmt.Fprintln(stderr)
		}
		return err
	}
	if done, err := flags.emit(stdout, result); done || err != nil {
		return err
	}
	printBrand(stdout)
	verb := "applied"
	if result.DryRun {
		// Said plainly, because the number that follows answers a different
		// question and a reader skimming would otherwise take it for a publication.
		verb = "would apply"
	}
	fmt.Fprintf(stdout, "📦  %s %d repository %s", verb, result.Applied, plural(result.Applied, "change", "changes"))
	if result.Current != 0 {
		fmt.Fprintf(stdout, " (%d already current)", result.Current)
	}
	fmt.Fprintln(stdout)
	if result.DryRun {
		fmt.Fprintln(stdout, "✉️   dry run: nothing was staged, recorded or published")
	}
	fmt.Fprintf(stdout, "✉️   plan sha256:%s\n", result.PlanID)
	return nil
}

func runApprove(args []string, stdout, stderr io.Writer) error {
	flags := newCommandFlags("approve", stderr).withWorkspace().withJSON()
	plan := flags.String("plan", defaultPlanFile, "reviewed plan file")
	output := flags.String("out", "", "approval evidence output")
	repository := flags.String("repository", "", "repository to approve")
	keyFile := flags.String("key", "", "Ed25519 approval private key file")
	expires := flags.Duration("expires", 30*time.Minute, "approval lifetime")
	yes := flags.Bool("yes", false, "confirm approval of the exact plan ID")
	if err := flags.parse(args); err != nil {
		return err
	}
	if !*yes {
		return errors.New("approval requires --yes after reviewing the exact plan")
	}
	result, err := engine.ApprovePlan(engine.ApprovePlanRequest{
		Root: flags.Root(), Plan: *plan, Output: *output, Repository: *repository,
		KeyFile: *keyFile, ExpiresIn: *expires,
	})
	if err != nil {
		return err
	}
	if done, err := flags.emit(stdout, result); done || err != nil {
		return err
	}
	printBrand(stdout)
	fmt.Fprintf(stdout, "📦  approved repository %s\n", *repository)
	fmt.Fprintf(stdout, "✉️   %s\n", result.Output)
	fmt.Fprintf(stdout, "    plan sha256:%s\n", result.PlanID)
	fmt.Fprintf(stdout, "    approver %s\n", result.Approver)
	return nil
}

func runApprovalKey(args []string, stdout, stderr io.Writer) error {
	// The subcommand word is consumed before parsing, because Go's flag package
	// stops at the first non-flag argument: parsing the whole tail left --out
	// unseen and rejected the documented invocation.
	if len(args) == 0 || args[0] != "generate" {
		return errors.New("usage: snailmail approval-key generate --out FILE")
	}
	flags := newCommandFlags("approval-key generate", stderr).withJSON()
	output := flags.String("out", "", "private key output file")
	if err := flags.parse(args[1:]); err != nil {
		return err
	}
	if *output == "" {
		return errors.New("usage: snailmail approval-key generate --out FILE")
	}
	publicKey, err := gate.GenerateApprovalKey(*output)
	if err != nil {
		return err
	}
	if done, err := flags.emit(stdout, approvalKeyResult{Output: *output, PublicKey: publicKey}); done || err != nil {
		return err
	}
	printBrand(stdout)
	fmt.Fprintln(stdout, "📦  generated Ed25519 approval key")
	fmt.Fprintf(stdout, "✉️   %s\n", *output)
	fmt.Fprintf(stdout, "    public key %s\n", publicKey)
	return nil
}

func runRender(args []string, stdout, stderr io.Writer) error {
	flags := newCommandFlags("dashboard", stderr).withWorkspace().withJSON()
	output := flags.String("output", "site", "output directory for the status page")
	plan := flags.String("plan", "snailmail.snailmail-plan.json", "optional plan used for pending gates")
	if err := flags.parse(args); err != nil {
		return err
	}
	result, err := engine.RenderStatus(engine.RenderStatusRequest{Root: flags.Root(), Output: *output, Plan: *plan})
	if err != nil {
		return err
	}
	if done, err := flags.emit(stdout, result); done || err != nil {
		return err
	}
	printBrand(stdout)
	fmt.Fprintf(stdout, "📦  rendered %d repository %s\n", result.Repositories, plural(result.Repositories, "status", "statuses"))
	fmt.Fprintf(stdout, "✉️   %s\n", result.Output)
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
	flags := newCommandFlags("build pypi", stderr).withJSON()
	input := flags.String("input", "", "directory containing wheels and source distributions")
	output := flags.String("output", "", "directory to write the static repository")
	generatedAtValue := flags.String("generated-at", defaultGeneratedAt, "explicit RFC3339 generation time")
	if err := flags.parse(args); err != nil {
		return err
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
	if done, err := flags.emit(stdout, result); done || err != nil {
		return err
	}
	printBrand(stdout)
	fmt.Fprintf(stdout, "📦  packed %d %s across %d %s\n", result.DistributionCount, plural(result.DistributionCount, "distribution", "distributions"), result.ProjectCount, plural(result.ProjectCount, "project", "projects"))
	fmt.Fprintf(stdout, "✉️   wrote %s to %s\n", result.Format, result.Output)
	fmt.Fprintf(stdout, "    tree sha256:%s\n", result.TreeSHA256)
	return nil
}

func runBuildDeb(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := newCommandFlags("build deb", stderr).withJSON()
	input := flags.String("input", "", "directory containing Debian packages")
	output := flags.String("output", "", "directory to write the static repository")
	suite := flags.String("suite", "stable", "Debian suite/codename")
	component := flags.String("component", "main", "Debian component")
	architecturesValue := flags.String("architectures", "amd64", "comma-separated target architectures")
	generatedAtValue := flags.String("generated-at", defaultGeneratedAt, "explicit RFC3339 generation time")
	if err := flags.parse(args); err != nil {
		return err
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
	if done, err := flags.emit(stdout, result); done || err != nil {
		return err
	}
	printBrand(stdout)
	fmt.Fprintf(stdout, "📦  indexed %d %s across %d %s\n", result.DistributionCount, plural(result.DistributionCount, "package file", "package files"), result.PackageCount, plural(result.PackageCount, "package", "packages"))
	fmt.Fprintf(stdout, "✉️   wrote %s to %s\n", result.Format, result.Output)
	fmt.Fprintf(stdout, "    tree sha256:%s\n", result.TreeSHA256)
	return nil
}

func runBuildHelm(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := newCommandFlags("build helm", stderr).withJSON()
	input := flags.String("input", "", "directory containing packaged Helm charts")
	output := flags.String("output", "", "directory to write the static repository")
	generatedAtValue := flags.String("generated-at", defaultGeneratedAt, "explicit RFC3339 generation time")
	if err := flags.parse(args); err != nil {
		return err
	}
	generatedAt, err := time.Parse(time.RFC3339, *generatedAtValue)
	if err != nil {
		return fmt.Errorf("parse --generated-at: %w", err)
	}
	result, err := engine.BuildHelm(ctx, engine.BuildHelmRequest{Input: *input, Output: *output, GeneratedAt: generatedAt})
	if err != nil {
		return err
	}
	if done, err := flags.emit(stdout, result); done || err != nil {
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
		return errors.New("usage: snailmail verify <pypi|deb|helm|raw|rpm|apk> [options]")
	}
	switch args[0] {
	case "pypi":
		return runVerifyPyPI(ctx, args[1:], stdout, stderr)
	case "deb":
		return runVerifyDeb(ctx, args[1:], stdout, stderr)
	case "helm":
		return runVerifyHelm(ctx, args[1:], stdout, stderr)
	case "raw":
		return runVerifyRaw(args[1:], stdout, stderr)
	case "rpm":
		return runVerifyRPM(ctx, args[1:], stdout, stderr)
	case "apk":
		return runVerifyAPK(ctx, args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown verify format %q", args[0])
	}
}

func runVerifyPyPI(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := newCommandFlags("verify pypi", stderr).withJSON()
	repository := flags.String("repo", "", "generated repository directory")
	python := flags.String("python", "python3", "Python executable whose pip client verifies installs")
	structuralOnly := flags.Bool("structural-only", false, "verify files and indexes without invoking pip")
	if err := flags.parse(args); err != nil {
		return err
	}
	result, err := engine.VerifyPyPI(ctx, engine.VerifyPyPIRequest{
		Repository:     *repository,
		Python:         *python,
		StructuralOnly: *structuralOnly,
	})
	if err != nil {
		return err
	}
	if done, err := flags.emit(stdout, result); done || err != nil {
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
	flags := newCommandFlags("verify deb", stderr).withJSON()
	repository := flags.String("repo", "", "generated repository directory")
	runner := flags.String("runner", "podman", "OCI runner executable")
	image := flags.String("image", engine.DefaultDebianVerificationImage, "digest-pinned Debian client image")
	maxWorkspaceMiB := flags.Int64("max-workspace-mib", 4096, "maximum temporary verification workspace in MiB")
	structuralOnly := flags.Bool("structural-only", false, "verify files and indexes without invoking apt")
	if err := flags.parse(args); err != nil {
		return err
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
	if done, err := flags.emit(stdout, result); done || err != nil {
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
	flags := newCommandFlags("verify helm", stderr).withJSON()
	repository := flags.String("repo", "", "generated repository directory")
	runner := flags.String("runner", "podman", "OCI runner executable")
	image := flags.String("image", engine.DefaultHelmVerificationImage, "digest-pinned Helm client image")
	structuralOnly := flags.Bool("structural-only", false, "verify files and index without invoking Helm")
	if err := flags.parse(args); err != nil {
		return err
	}
	result, err := engine.VerifyHelm(ctx, engine.VerifyHelmRequest{Repository: *repository, Runner: *runner, Image: *image, StructuralOnly: *structuralOnly})
	if err != nil {
		return err
	}
	if done, err := flags.emit(stdout, result); done || err != nil {
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

// runVerifyRaw takes no runner or client flags: raw has no ecosystem client to
// install with, so checking the tree against its own checksums is the whole
// verification rather than a structural subset of one.
func runVerifyRaw(args []string, stdout, stderr io.Writer) error {
	flags := newCommandFlags("verify raw", stderr).withJSON()
	repository := flags.String("repo", "", "generated repository directory")
	if err := flags.parse(args); err != nil {
		return err
	}
	result, err := engine.VerifyRaw(engine.VerifyRawRequest{Repository: *repository})
	if err != nil {
		return err
	}
	if done, err := flags.emit(stdout, result); done || err != nil {
		return err
	}
	printBrand(stdout)
	fmt.Fprintf(stdout, "📦  verified %d repository %s\n", result.FileCount, plural(result.FileCount, "file", "files"))
	fmt.Fprintf(stdout, "✉️   listing and checksums cover %d package %s\n",
		result.InstalledCases, plural(result.InstalledCases, "version", "versions"))
	fmt.Fprintf(stdout, "    tree sha256:%s\n", result.TreeSHA256)
	return nil
}

// runVersion reports what this binary is. The version is stamped from the Git
// tag at link time, so an ordinary `go build` reports a revision rather than
// claiming a release it is not.
func runVersion(args []string, stdout, stderr io.Writer) error {
	flags := newCommandFlags("version", stderr).withJSON()
	if err := flags.parse(args); err != nil {
		return err
	}
	build := version.Current()
	if done, err := flags.emit(stdout, build); done || err != nil {
		return err
	}
	printBrand(stdout)
	fmt.Fprintf(stdout, "\u2709\ufe0f   %s\n", build.String())
	if !build.IsRelease() {
		fmt.Fprintln(stdout, "    not a release build; nothing here may be published as one")
	}
	return nil
}

func runVerifyRPM(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := newCommandFlags("verify rpm", stderr).withJSON()
	repository := flags.String("repo", "", "generated repository directory")
	runner := flags.String("runner", "podman", "OCI runner executable")
	allVersions := flags.Bool("all-versions", false, "install every retained version, not the newest and oldest of each")
	image := flags.String("image", engine.DefaultRPMVerificationImage, "digest-pinned RPM client image")
	structuralOnly := flags.Bool("structural-only", false, "verify indexes without invoking dnf")
	if err := flags.parse(args); err != nil {
		return err
	}
	result, err := engine.VerifyRPM(ctx, engine.VerifyRPMRequest{
		Repository: *repository, Runner: *runner, Image: *image, StructuralOnly: *structuralOnly,
		VerifyAllVersions: *allVersions,
	})
	if err != nil {
		return err
	}
	if done, err := flags.emit(stdout, result); done || err != nil {
		return err
	}
	printBrand(stdout)
	fmt.Fprintf(stdout, "📦  verified %d repository %s\n", result.FileCount, plural(result.FileCount, "file", "files"))
	if *structuralOnly {
		fmt.Fprintln(stdout, "✉️   structural verification passed")
	} else {
		fmt.Fprintf(stdout, "✉️   dnf installed %d %s\n", result.InstalledCases, plural(result.InstalledCases, "package", "packages"))
	}
	fmt.Fprintf(stdout, "    tree sha256:%s\n", result.TreeSHA256)
	return nil
}

func runVerifyAPK(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := newCommandFlags("verify apk", stderr).withJSON()
	repository := flags.String("repo", "", "generated repository directory")
	runner := flags.String("runner", "podman", "OCI runner executable")
	allVersions := flags.Bool("all-versions", false, "install every retained version, not the newest and oldest of each")
	image := flags.String("image", engine.DefaultAPKVerificationImage, "digest-pinned Alpine client image")
	structuralOnly := flags.Bool("structural-only", false, "verify the index without invoking apk")
	if err := flags.parse(args); err != nil {
		return err
	}
	result, err := engine.VerifyAPK(ctx, engine.VerifyAPKRequest{
		Repository: *repository, Runner: *runner, Image: *image, StructuralOnly: *structuralOnly,
		VerifyAllVersions: *allVersions,
	})
	if err != nil {
		return err
	}
	if done, err := flags.emit(stdout, result); done || err != nil {
		return err
	}
	printBrand(stdout)
	fmt.Fprintf(stdout, "📦  verified %d repository %s\n", result.FileCount, plural(result.FileCount, "file", "files"))
	if *structuralOnly {
		fmt.Fprintln(stdout, "✉️   structural verification passed")
	} else {
		fmt.Fprintf(stdout, "✉️   apk installed %d %s\n", result.InstalledCases, plural(result.InstalledCases, "package", "packages"))
	}
	fmt.Fprintf(stdout, "    tree sha256:%s\n", result.TreeSHA256)
	return nil
}

func runServe(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := newCommandFlags("serve", stderr)
	repository := flags.String("repo", "", "generated repository directory")
	listenAddress := flags.String("listen", "127.0.0.1:8080", "HTTP listen address")
	if err := flags.parse(args); err != nil {
		return err
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

// printUsage groups commands by when someone reaches for them.
//
// A flat list of thirty-nine usage lines is accurate and useless to a newcomer:
// blob-store, keys rotate and dashboard sat at the same visual level as add and
// apply, and apply — the command that actually publishes — was the thirty-second
// line. The grammar lines were never the problem; the absence of an order was.
func printUsage(output io.Writer) {
	printBrand(output)
	fmt.Fprintln(output, "relaxed package delivery")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "  Publishing is: add an artifact, review the diff, plan, apply.")
	fmt.Fprintln(output, "  Everything a plan will do is visible before it does it.")

	for _, group := range []struct {
		title    string
		commands []string
	}{
		{"Start here", []string{
			"init --name NAME",
			"setup <pypi|deb|helm|raw|rpm|apk> --name NAME --output DIR",
			"setup pypi --name NAME --host s3 --bucket BUCKET --base-url URL [--prefix PREFIX --region REGION]",
			"setup rpm --name NAME --host rsync --target USER@HOST --output /abs/remote/path",
		}},
		{"Every day", []string{
			"add [--name NAME --version VERSION] REPOSITORY ARTIFACT...",
			"plan [--out snailmail.snailmail-plan.json]",
			"apply [--plan snailmail.snailmail-plan.json] [--dry-run]",
			"status [--workspace DIR] [--json]",
		}},
		{"Curating what is published", []string{
			"promote [--track stable] [--distro DISTRO] REPOSITORY PACKAGE VERSION",
			"yank (--track TRACK [--distro DISTRO] | --all) REPOSITORY PACKAGE VERSION",
			"prune REPOSITORY --keep N",
			"rollout [--repo NAME] [--package NAME] [--withdrawn]",
			"collect [--repo NAME] [--keep N] [--yes]",
			"rollback REPOSITORY [--yes]",
		}},
		{"Taking on an existing repository", []string{
			"import --public-origin [--project NAME|--suite NAME] [--min-provenance LEVEL] [--dry-run --limit N] REPOSITORY URL",
			"adopt --sha256 HEX --public-origin [--filename NAME --track TRACK] REPOSITORY URL",
			"doctor [--format auto|pypi|deb|helm] [--json] URL",
		}},
		{"Signing and review gates", []string{
			"keys new NAME [--algo openpgp-rsa4096]",
			"keys attach REPOSITORY --key NAME",
			"keys publish NAME",
			"keys rotate REPOSITORY --successor KEY [--minimum-refresh 720h]",
			"keys rotate REPOSITORY --advance --yes",
			"keys audit",
			"approval-key generate --out FILE",
			"approve --plan PLAN --repository NAME --key FILE --yes",
		}},
		{"Checking and inspecting", []string{
			"check [--workspace DIR] [--json] [--origins --max-origins N --origin-offset N]",
			"verify <pypi|deb|helm|raw|rpm|apk> --repo DIR [--runner podman]",
			"serve --repo DIR [--listen 127.0.0.1:8080]",
			"version [--json]",
		}},
		{"Pages, sites and CI", []string{
			"site [--title TITLE] [--description TEXT] [--output PATH]",
			"dashboard [--output site]",
			"ci <github|gitlab> [--snailmail-version vX.Y.Z] > .github/workflows/publish.yml",
		}},
		{"Building a repository without a workspace", []string{
			"build <pypi|deb|helm> --input DIR --output DIR [--suite stable --architectures amd64]",
			"blob-store s3 --bucket BUCKET [--prefix PREFIX --region REGION]",
		}},
	} {
		fmt.Fprintln(output)
		fmt.Fprintf(output, "%s:\n", group.title)
		for _, command := range group.commands {
			fmt.Fprintf(output, "  snailmail %s\n", command)
		}
	}
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Flags may appear anywhere, and every command that reports a result accepts --json.")
	fmt.Fprintln(output, "--workspace DIR works on every command that reads a workspace.")
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

func verificationMode(structuralOnly bool) string {
	if structuralOnly {
		return "structural"
	}
	return "client"
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

// These commands complete an action rather than compute a result, so the typed
// value both renderings read is declared here. ARCHITECTURE §5.3 requires the
// two renderings to share one value; what matters is that they cannot drift,
// not where the value is declared.

type initResult struct {
	Workspace            string `json:"workspace"`
	CreatedGitRepository bool   `json:"created_git_repository,omitempty"`
	Committed            bool   `json:"committed,omitempty"`
}

type setupResult struct {
	Repository string `json:"repository"`
	Format     string `json:"format"`
	Target     string `json:"target"`
}

type blobStoreResult struct {
	Type string `json:"type"`
}

type approvalKeyResult struct {
	Output    string `json:"output"`
	PublicKey string `json:"public_key"`
}

type publishKeyResult struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
}

// applyProgress renders apply events as they happen.
//
// To stderr, so stdout carries only the result and --json stays machine-readable.
// Suppressed under --json for the same reason a caller asked for JSON: it wants
// one document, not a narration around it.
//
// Serialised, because repositories are prepared concurrently and two goroutines
// writing a line each would interleave them.
func applyProgress(stderr io.Writer, quiet bool) engine.ApplyProgress {
	if quiet {
		return nil
	}
	var mutex sync.Mutex
	started := time.Now()
	return func(event engine.ApplyEvent) {
		mutex.Lock()
		defer mutex.Unlock()
		elapsed := time.Since(started).Round(time.Second)
		where := event.Repository
		if where == "" {
			where = plural(event.Total, "repository", "repositories")
			if event.Total != 0 {
				where = fmt.Sprintf("%d %s", event.Total, where)
			}
		} else if event.Total > 1 {
			where = fmt.Sprintf("%s (%d/%d)", where, event.Index, event.Total)
		}
		line := fmt.Sprintf("   %5s  %-9s %s", elapsed, event.Phase, where)
		if event.Detail != "" {
			line += "  " + event.Detail
		}
		fmt.Fprintln(stderr, line)
	}
}

// humanBytes renders a size the way an operator reads one. Deliberately coarse:
// the question this answers is "is this getting large", not "exactly how large".
func humanBytes(bytes int64) string {
	switch {
	case bytes >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(bytes)/(1<<30))
	case bytes >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(bytes)/(1<<20))
	case bytes >= 1<<10:
		return fmt.Sprintf("%.0f KiB", float64(bytes)/(1<<10))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// largestLockSuffix names the biggest lock when there is more than one, because
// "3 GiB across ten repositories" does not say which one to split.
func largestLockSuffix(result engine.StatusWorkspaceResult) string {
	if len(result.Repositories) < 2 {
		return ""
	}
	largest := result.Repositories[0]
	for _, repository := range result.Repositories[1:] {
		if repository.LockBytes > largest.LockBytes {
			largest = repository
		}
	}
	if largest.LockBytes == 0 {
		return ""
	}
	return fmt.Sprintf(", largest %s at %s", largest.Name, humanBytes(largest.LockBytes))
}

// defaultPlanFile is where plan writes and apply reads when neither is told
// otherwise. Named because a next-step hint has to agree with it, and three flags
// repeated the literal.
const defaultPlanFile = "snailmail.snailmail-plan.json"

func runRollback(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := newCommandFlags("rollback", stderr).withWorkspace().withJSON()
	dryRun := flags.Bool("dry-run", false, "report what would be restored without restoring it")
	// Undoing a publication is destructive in the same sense collect is: it changes
	// what the world is being served. So it asks, the way collect and yank do.
	yes := flags.Bool("yes", false, "confirm the rollback; without it this reports what would happen")
	positional, err := flags.parseWithArguments(args, 1, "usage: snailmail rollback [options] REPOSITORY")
	if err != nil {
		return err
	}
	hosts := wire.NewHostResolver()
	defer hosts.Close()
	result, err := engine.RollbackRepository(ctx, engine.RollbackRepositoryRequest{
		Root: flags.Root(), Repository: positional[0], DryRun: *dryRun || !*yes, Hosts: hosts,
	})
	if err != nil {
		return err
	}
	if done, err := flags.emit(stdout, result); done || err != nil {
		return err
	}
	printBrand(stdout)
	if result.DryRun {
		fmt.Fprintf(stdout, "\U0001F4E6  would roll %s back from %s\n", result.Repository, shortDigest(result.From))
		fmt.Fprintf(stdout, "\u2192   next: snailmail rollback --yes %s   (actually restore the previous publication)\n", result.Repository)
		return nil
	}
	fmt.Fprintf(stdout, "\U0001F4E6  rolled %s back from %s to %s\n",
		result.Repository, shortDigest(result.From), shortDigest(result.To))
	if result.Note != "" {
		fmt.Fprintf(stdout, "\u26A0\uFE0F   %s\n", result.Note)
	}
	return nil
}

// shortDigest is a tree digest abbreviated for reading, since a rollback message
// is about which of two revisions is live rather than about their full identity.
func shortDigest(digest string) string {
	if len(digest) <= 12 {
		return digest
	}
	return digest[:12]
}

func runCollect(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := newCommandFlags("collect", stderr).withWorkspace().withJSON()
	repository := flags.String("repo", "", "collect one repository")
	keep := flags.Int("keep", 0,
		"override the retention this repository declares, for one run")
	// Reporting is the default and deleting needs saying, which is how every other
	// command here that destroys something behaves.
	yes := flags.Bool("yes", false, "actually remove; without it this reports what would be removed")
	if err := flags.parse(args); err != nil {
		return err
	}
	hosts := wire.NewHostResolver()
	defer hosts.Close()
	// Only an override when the operator actually asked for one; otherwise the
	// repository's declared retention applies.
	var override *int
	if flags.wasSet("keep") {
		override = keep
	}
	result, err := engine.CollectWorkspace(ctx, engine.CollectWorkspaceRequest{
		Root: flags.Root(), Repository: *repository, Keep: override, Apply: *yes, Hosts: hosts,
	})
	if err != nil {
		return err
	}
	if done, err := flags.emit(stdout, result); done || err != nil {
		return err
	}
	printBrand(stdout)
	for _, reported := range result.Repositories {
		if !reported.Collectable {
			fmt.Fprintf(stdout, "✉️   %s: %s\n", reported.Name, reported.Note)
			continue
		}
		fmt.Fprintf(stdout, "✉️   %s: %d %s (%s), %d %s kept\n",
			reported.Name, reported.Removed, plural(reported.Removed, "object", "objects"),
			humanBytes(reported.RemovedBytes), reported.KeptRevisions,
			plural(reported.KeptRevisions, "revision", "revisions"))
	}
	verb := "would remove"
	if result.Applied {
		verb = "removed"
	}
	fmt.Fprintf(stdout, "📦  %s %d %s, %s\n", verb, result.Removed,
		plural(result.Removed, "object", "objects"), humanBytes(result.RemovedBytes))
	if !result.Applied && result.Removed != 0 {
		fmt.Fprintln(stdout, "✉️   nothing was removed; pass --yes to collect")
	}
	return nil
}

// suggestNext prints the command that usually comes next.
//
// Five commands stand between an empty directory and a published repository, and
// nothing in any of them said what the next one was — so the sequence lived only
// in the README, which is exactly where someone who has already started is not
// looking. Printing it puts the path where the person following it already is.
//
// Suppressed under --json, because a caller asking for one machine-readable
// document does not want advice around it.
func suggestNext(stdout io.Writer, flags *commandFlags, command, purpose string) {
	if flags.jsonRequested() {
		return
	}
	fmt.Fprintf(stdout, "→   next: %s   (%s)\n", command, purpose)
}

func runImport(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := newCommandFlags("import", stderr).withWorkspace().withJSON()
	project := flags.String("project", "", "PyPI project to read")
	suite := flags.String("suite", "", "Debian suite to read, such as bookworm")
	component := flags.String("component", "", "Debian component, defaulting to the first Release names")
	architecture := flags.String("architecture", "", "Debian architecture, defaulting to the first Release names")
	track := flags.String("track", "", "track to place imported versions on")
	distro := flags.String("distro", "", "distribution to place imported versions on")
	limit := flags.Int("limit", 0, "import at most this many artifacts")
	minProvenance := flags.String("min-provenance", "",
		"refuse artifacts whose digest was established more weakly than this: signed-index, index-chain, index-stated, or computed")
	dryRun := flags.Bool("dry-run", false, "report what would be imported without recording it")
	publicOrigin := flags.Bool("public-origin", false,
		"confirm the recorded origin URLs are public and contain no secrets")
	positional, err := flags.parseWithArguments(args, 2,
		"usage: snailmail import --project NAME --public-origin [--dry-run --limit N] REPOSITORY URL")
	if err != nil {
		return err
	}
	if *minProvenance != "" && !state.ValidProvenance(state.DigestProvenance(*minProvenance)) {
		return fmt.Errorf("unknown --min-provenance %q: use signed-index, index-chain, index-stated, or computed",
			*minProvenance)
	}
	result, err := engine.ImportRepository(ctx, engine.ImportRepositoryRequest{
		Root: flags.Root(), Repository: positional[0], URL: positional[1],
		Project: *project, Suite: *suite, Component: *component, Architecture: *architecture,
		Track: *track, Distro: *distro, Limit: *limit,
		MinimumProvenance: state.DigestProvenance(*minProvenance),
		DryRun:            *dryRun, PublicOrigin: *publicOrigin, Fetcher: httpsource.New(),
	})
	if err != nil {
		return err
	}
	if done, err := flags.emit(stdout, result); done || err != nil {
		return err
	}
	printBrand(stdout)
	verb := "imported"
	if result.DryRun {
		verb = "would import"
	}
	fmt.Fprintf(stdout, "📦  %s %d of %d %s from %s\n", verb, len(result.Imported), result.Listed,
		plural(result.Listed, "artifact", "artifacts"), result.IndexURL)
	for _, imported := range result.Imported {
		fmt.Fprintf(stdout, "✉️   %s@%s sha256:%s\n", imported.Package, imported.Version, imported.SHA256)
	}
	// Skipped artifacts are named rather than counted. An import that took nine of
	// ten and said only "9 imported" would be discovered later, by a client.
	for _, skipped := range result.Skipped {
		fmt.Fprintf(stdout, "⚠️   skipped %s: %s\n", skipped.Filename, skipped.Reason)
	}
	if result.DryRun && len(result.Imported) != 0 {
		fmt.Fprintln(stdout, "✉️   nothing was recorded; drop --dry-run to import")
	} else if len(result.Imported) != 0 {
		suggestNext(stdout, flags, "git commit -am \"import "+positional[0]+"\" && snailmail plan",
			"review what was imported as a diff, then publish it")
	}
	return nil
}
