package rsynchost

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Runner executes a command on the far side of a publication.
//
// A port rather than direct exec.Command, for the same reason the forge has one:
// the adapter's logic is about renames and locks, and none of it should need an
// ssh daemon to test. The ssh runner is what production uses; tests use one that
// runs the same commands in a local directory, so what is exercised is the
// sequence of operations rather than a simulation of it.
type Runner interface {
	// Run executes argv on the target and returns its standard output. argv is a
	// command and its arguments, never a shell string — the adapter builds paths
	// from a repository name and a tree digest, and passing those through a shell
	// would be an injection surface for no benefit.
	Run(ctx context.Context, argv []string) ([]byte, error)
	// Send copies a local directory tree to a path on the target, replacing
	// whatever is there.
	Send(ctx context.Context, localDirectory, remotePath string) error
}

// ErrCommandFailed is returned when a remote command exits non-zero. The adapter
// distinguishes an expected failure — mkdir on a lock that exists, readlink on a
// path that does not — from a transport failure, and both arrive this way, so the
// exit status is carried rather than flattened.
type ErrCommandFailed struct {
	Argv     []string
	ExitCode int
	Stderr   string
}

func (err *ErrCommandFailed) Error() string {
	return fmt.Sprintf("%s exited %d: %s", strings.Join(err.Argv, " "), err.ExitCode, strings.TrimSpace(err.Stderr))
}

// exitCode reports a remote command's exit status, and whether it had one.
func exitCode(err error) (int, bool) {
	var failed *ErrCommandFailed
	if errors.As(err, &failed) {
		return failed.ExitCode, true
	}
	return 0, false
}

// SSHRunner runs commands on a remote host over ssh and copies trees with rsync.
type SSHRunner struct {
	// Target is what ssh is given: a host, or user@host, or a name configured in
	// ssh_config. Options beyond that — port, key, jump host — belong in
	// ssh_config rather than being re-expressed here, because an operator already
	// has somewhere to put them and a second place to configure ssh is a second
	// place for it to be wrong.
	Target string
	// SSHCommand and RsyncCommand override the binaries, for a host that ships
	// them elsewhere. Empty means "ssh" and "rsync" from PATH.
	SSHCommand   string
	RsyncCommand string
}

func (runner *SSHRunner) ssh() string {
	if runner.SSHCommand != "" {
		return runner.SSHCommand
	}
	return "ssh"
}

func (runner *SSHRunner) Run(ctx context.Context, argv []string) ([]byte, error) {
	if runner.Target == "" {
		return nil, errors.New("ssh target is required")
	}
	// The remote argv is passed as separate arguments to ssh, which joins them
	// with spaces before the remote shell sees them. Each is quoted so a path
	// containing a space or a shell metacharacter survives that round trip.
	arguments := append([]string{runner.Target}, quoteAll(argv)...)
	command := exec.CommandContext(ctx, runner.ssh(), arguments...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return stdout.Bytes(), &ErrCommandFailed{Argv: argv, ExitCode: exit.ExitCode(), Stderr: stderr.String()}
		}
		return stdout.Bytes(), fmt.Errorf("run ssh: %w", err)
	}
	return stdout.Bytes(), nil
}

func (runner *SSHRunner) Send(ctx context.Context, localDirectory, remotePath string) error {
	if runner.Target == "" {
		return errors.New("ssh target is required")
	}
	binary := runner.RsyncCommand
	if binary == "" {
		binary = "rsync"
	}
	// --delete so the destination matches the source exactly. The destination is
	// always a temporary directory this adapter created, never the live tree, so
	// there is nothing of anyone else's to delete.
	command := exec.CommandContext(ctx, binary,
		"--archive", "--delete", "--checksum",
		"--rsh", runner.ssh(),
		strings.TrimSuffix(localDirectory, "/")+"/",
		runner.Target+":"+remotePath+"/")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return &ErrCommandFailed{
				Argv: []string{binary, localDirectory, remotePath}, ExitCode: exit.ExitCode(), Stderr: stderr.String(),
			}
		}
		return fmt.Errorf("run rsync: %w", err)
	}
	return nil
}

// quoteAll single-quotes each argument for the remote shell ssh invokes.
func quoteAll(argv []string) []string {
	quoted := make([]string, 0, len(argv))
	for _, argument := range argv {
		quoted = append(quoted, "'"+strings.ReplaceAll(argument, "'", `'\''`)+"'")
	}
	return quoted
}
