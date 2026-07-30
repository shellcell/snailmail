package rsynchost

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shellcell/snailmail/formats/pypi"
	"github.com/shellcell/snailmail/host"
	"github.com/shellcell/snailmail/internal/app"
	"github.com/shellcell/snailmail/internal/buildgraph"
	"github.com/shellcell/snailmail/internal/testutil"
)

// localRunner executes the adapter's commands on this machine instead of over ssh.
//
// The same binaries — readlink, mkdir, mv -T, ln -sfn — run against a real
// filesystem, so what these tests exercise is the actual sequence of operations and
// the actual semantics of rename and mkdir, not a model of them. What is not
// covered is ssh itself: transport failures and quoting are the runner's business
// and are tested separately.
type localRunner struct {
	commands [][]string
	failOn   string
}

func (runner *localRunner) Run(ctx context.Context, argv []string) ([]byte, error) {
	runner.commands = append(runner.commands, argv)
	if runner.failOn != "" && argv[0] == runner.failOn {
		return nil, &ErrCommandFailed{Argv: argv, ExitCode: 1, Stderr: "forced failure"}
	}
	command := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return stdout.Bytes(), &ErrCommandFailed{Argv: argv, ExitCode: exit.ExitCode(), Stderr: stderr.String()}
		}
		return stdout.Bytes(), err
	}
	return stdout.Bytes(), nil
}

func (runner *localRunner) Send(_ context.Context, localDirectory, remotePath string) error {
	if err := os.RemoveAll(remotePath); err != nil {
		return err
	}
	return os.CopyFS(remotePath, os.DirFS(localDirectory))
}

func (runner *localRunner) ran(name string) bool {
	for _, argv := range runner.commands {
		if argv[0] == name {
			return true
		}
	}
	return false
}

// verifiedTree builds a repository the adapter will accept, since Stage verifies
// before sending anything to the far side.
func verifiedTree(t *testing.T, version string) (string, string) {
	t.Helper()
	input := t.TempDir()
	if _, err := testutil.WriteWheel(input, "rsync-demo", version, ""); err != nil {
		t.Fatal(err)
	}
	snapshot, err := app.ScanPyPI(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	artifact, err := pypi.Build(snapshot.Blobs)
	if err != nil {
		t.Fatal(err)
	}
	artifact, _, err = buildgraph.Finalize(artifact, time.Date(2026, time.July, 25, 1, 2, 3, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "repository")
	if err := app.Materialize(context.Background(), directory, artifact, snapshot.Sources); err != nil {
		t.Fatal(err)
	}
	release, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := app.VerifyRepository(release)
	if err != nil {
		t.Fatal(err)
	}
	return release, manifest.TreeSHA256
}

func publishedRepository(t *testing.T) (host.Repository, string) {
	t.Helper()
	base := t.TempDir()
	return host.Repository{
		Name: "apt", Format: "raw", Type: "rsync",
		Path:              filepath.Join(base, "www"),
		CanonicalEndpoint: "https://packages.example/apt",
	}, base
}

func publish(t *testing.T, adapter *Adapter, repository host.Repository, version string,
	expected host.ExpectedRevision) (host.CommitResult, error) {
	t.Helper()
	directory, tree := verifiedTree(t, version)
	staged, err := adapter.Stage(context.Background(), repository, host.StageRequest{
		Directory: directory, TreeSHA256: tree, PlanID: "plan-" + version, ChangeID: "change-" + version,
	})
	if err != nil {
		t.Fatal(err)
	}
	return adapter.Commit(context.Background(), repository, staged, expected)
}

// The whole point: a publication lands and is served through a symlink, so a
// client follows one whole revision or another and never a partial tree.
func TestAPublicationBecomesLiveThroughASymlink(t *testing.T) {
	runner := &localRunner{}
	adapter := New(runner)
	repository, _ := publishedRepository(t)

	committed, err := publish(t, adapter, repository, "1.0.0", host.ExpectedRevision{})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(repository.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Error("the published path is not a symlink, so a publication is not atomic")
	}
	body, err := os.ReadFile(filepath.Join(repository.Path, "simple", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("rsync-demo")) {
		t.Errorf("the served index does not name the published project: %.80q", body)
	}
	// And Observe reads back what was published, which is what makes the next
	// publication's conditional check possible.
	observed, err := adapter.Observe(context.Background(), repository)
	if err != nil {
		t.Fatal(err)
	}
	if observed.TreeSHA256 != committed.Revision.TreeSHA256 {
		t.Errorf("observed %q, published %q", observed.TreeSHA256, committed.Revision.TreeSHA256)
	}
}

// A second publication replaces the first, and the swap is a rename over the
// existing symlink rather than a move into the directory it points at.
func TestASecondPublicationReplacesTheFirst(t *testing.T) {
	adapter := New(&localRunner{})
	repository, _ := publishedRepository(t)

	first, err := publish(t, adapter, repository, "1.0.0", host.ExpectedRevision{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publish(t, adapter, repository, "2.0.0",
		host.ExpectedRevision{TreeSHA256: first.Revision.TreeSHA256}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(repository.Path, "simple", "rsync-demo", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("2.0.0")) {
		t.Errorf("the second publication is not being served: %.120q", body)
	}
	// Not nested: a rename without -T would have moved the new symlink inside the
	// directory the old one pointed at, leaving the old revision served.
	if _, err := os.Stat(filepath.Join(repository.Path, filepath.Base(repository.Path))); err == nil {
		t.Error("the new symlink was moved inside the old revision instead of replacing it")
	}
}

// The conditional. A publication that expects a revision other than the live one is
// refused, which is what stops a runner with a stale plan from overwriting work it
// never saw.
func TestAStalePublicationIsRefused(t *testing.T) {
	adapter := New(&localRunner{})
	repository, _ := publishedRepository(t)

	first, err := publish(t, adapter, repository, "1.0.0", host.ExpectedRevision{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publish(t, adapter, repository, "2.0.0",
		host.ExpectedRevision{TreeSHA256: first.Revision.TreeSHA256}); err != nil {
		t.Fatal(err)
	}
	// A third runner still believing the first revision is live.
	_, err = publish(t, adapter, repository, "3.0.0",
		host.ExpectedRevision{TreeSHA256: first.Revision.TreeSHA256})
	if err == nil {
		t.Fatal("a stale publication overwrote a revision it did not expect")
	}
	var hostErr *host.Error
	if !errors.As(err, &hostErr) || hostErr.Kind != host.ErrorStale {
		t.Errorf("error kind = %v, want stale", err)
	}
	body, _ := os.ReadFile(filepath.Join(repository.Path, "simple", "rsync-demo", "index.html"))
	if !bytes.Contains(body, []byte("2.0.0")) {
		t.Error("the live revision changed despite the refusal")
	}
}

// Re-applying one plan is not a second publication, the same answer the object
// store gives for a retried CI job.
func TestRepublishingTheLiveRevisionIsNotASecondPublication(t *testing.T) {
	adapter := New(&localRunner{})
	repository, _ := publishedRepository(t)

	if _, err := publish(t, adapter, repository, "1.0.0", host.ExpectedRevision{}); err != nil {
		t.Fatal(err)
	}
	// The same tree again, with an expectation that is now wrong — it is already
	// live, so there is nothing to refuse.
	if _, err := publish(t, adapter, repository, "1.0.0", host.ExpectedRevision{}); err != nil {
		t.Errorf("re-applying the live revision was refused: %v", err)
	}
}

// The lock is what stands in for a compare-and-swap. A lock already held means one
// publication fails rather than one waits, which is the answer everywhere else.
func TestAHeldLockRefusesAPublication(t *testing.T) {
	adapter := New(&localRunner{})
	repository, base := publishedRepository(t)
	if err := os.MkdirAll(filepath.Join(base, lockDirectory), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := publish(t, adapter, repository, "1.0.0", host.ExpectedRevision{})
	if err == nil {
		t.Fatal("a publication proceeded while another held the lock")
	}
	if !strings.Contains(err.Error(), "another publication") {
		t.Errorf("error = %v, want the held lock named", err)
	}
}

// And the lock is released, or the next publication would be refused forever.
func TestTheLockIsReleasedAfterAPublication(t *testing.T) {
	adapter := New(&localRunner{})
	repository, base := publishedRepository(t)
	if _, err := publish(t, adapter, repository, "1.0.0", host.ExpectedRevision{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, lockDirectory)); !os.IsNotExist(err) {
		t.Error("the publication lock was left behind")
	}
}

// A path that already holds somebody's files must not be replaced by a symlink,
// which would unpublish them. This is the one destructive mistake the adapter is
// positioned to make.
func TestAnUnrelatedDirectoryIsNotReplaced(t *testing.T) {
	adapter := New(&localRunner{})
	repository, _ := publishedRepository(t)
	if err := os.MkdirAll(repository.Path, 0o755); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(repository.Path, "somebody-elses-file")
	if err := os.WriteFile(existing, []byte("keep me"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := publish(t, adapter, repository, "1.0.0", host.ExpectedRevision{})
	if err == nil {
		t.Fatal("a publication replaced a directory it did not create")
	}
	if _, err := os.Stat(existing); err != nil {
		t.Error("the existing directory's contents were destroyed")
	}
}

// A path that is not there yet is the first publication, and must work.
func TestAnAbsentPathIsTheFirstPublication(t *testing.T) {
	adapter := New(&localRunner{})
	repository, _ := publishedRepository(t)
	if _, err := publish(t, adapter, repository, "1.0.0", host.ExpectedRevision{}); err != nil {
		t.Fatalf("the first publication failed: %v", err)
	}
}

// Configuration refused early, because each of these would otherwise be discovered
// only after a tree had been copied to the far side.
func TestRefusedConfigurations(t *testing.T) {
	adapter := New(&localRunner{})
	for name, repository := range map[string]host.Repository{
		"no path":         {Name: "apt"},
		"relative path":   {Name: "apt", Path: "www/apt"},
		"filesystem root": {Name: "apt", Path: "/"},
	} {
		if _, err := adapter.Capabilities(context.Background(), repository); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// Observe reports no revision for a symlink this adapter did not write, rather than
// reading a tree digest out of a path that means something else.
func TestObserveIgnoresASymlinkItDidNotWrite(t *testing.T) {
	adapter := New(&localRunner{})
	repository, base := publishedRepository(t)
	elsewhere := filepath.Join(base, "elsewhere")
	if err := os.MkdirAll(elsewhere, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, repository.Path); err != nil {
		t.Fatal(err)
	}
	observed, err := adapter.Observe(context.Background(), repository)
	if err != nil {
		t.Fatal(err)
	}
	if observed.TreeSHA256 != "" {
		t.Errorf("observed %q from a symlink snailmail did not write", observed.TreeSHA256)
	}
}

// Abort removes the staging directory. A release already renamed into place stays:
// it is named by its digest, nothing points at it, and removing it is collection's
// job.
func TestAbortRemovesTheStagingDirectory(t *testing.T) {
	runner := &localRunner{}
	adapter := New(runner)
	repository, base := publishedRepository(t)
	directory, tree := verifiedTree(t, "1.0.0")
	staged, err := adapter.Stage(context.Background(), repository, host.StageRequest{
		Directory: directory, TreeSHA256: tree, PlanID: "p", ChangeID: "c",
	})
	if err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(base, stagingDirectory, tree)
	if err := os.MkdirAll(staging, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Abort(context.Background(), repository, staged); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(staging); !os.IsNotExist(err) {
		t.Error("abort left the staging directory behind")
	}
}

// Restore is declined rather than half-offered, so a caller finds out from a
// sentence instead of from a rollback that did not verify anything.
func TestRestoreIsDeclined(t *testing.T) {
	adapter := New(&localRunner{})
	repository, _ := publishedRepository(t)
	_, err := adapter.Restore(context.Background(), repository, host.RestoreRef{}, host.ExpectedRevision{})
	if err == nil {
		t.Fatal("restore was offered")
	}
	if !strings.Contains(err.Error(), "verify") {
		t.Errorf("error = %v, want the reason stated", err)
	}
}

func TestTheAdapterIsAHost(t *testing.T) {
	var _ host.Host = New(&localRunner{})
}
