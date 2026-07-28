package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withGitLockOwnerRunning(t *testing.T, running func(int) bool) {
	t.Helper()
	previous := gitLockOwnerIsRunning
	gitLockOwnerIsRunning = running
	t.Cleanup(func() { gitLockOwnerIsRunning = previous })
}

// A lock whose owner is still alive is reported as busy, not as recoverable
// wreckage, so the message must not invite anyone to delete it.
func TestGitLockConflictReportsRunningOwnerAsBusy(t *testing.T) {
	directory := t.TempDir()
	blocked := filepath.Join(directory, "index.lock")
	withGitLockOwnerRunning(t, func(int) bool { return true })
	held := gitLockOwnerPrefix + "\npid=4242\nsince=2026-01-01T00:00:00Z\n"
	if err := os.WriteFile(blocked, []byte(held), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := acquireGitLock(blocked)
	if err == nil {
		t.Fatal("expected acquiring an existing lock to fail")
	}
	message := describeGitLockConflict(blocked, []string{blocked}, err).Error()
	if !strings.Contains(message, "running snailmail process") {
		t.Fatalf("message %q does not report a live owner", message)
	}
	if strings.Contains(message, "remove") {
		t.Fatalf("a lock a live process holds must not be recommended for removal: %q", message)
	}
}

func TestGitLockRecordsItsOwner(t *testing.T) {
	name := filepath.Join(t.TempDir(), "index.lock")
	release, err := acquireGitLock(name)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	content, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(content), gitLockOwnerPrefix) {
		t.Fatalf("lock file does not record its owner: %q", content)
	}
	pid, found := gitLockOwnerProcess(content)
	if !found || pid != os.Getpid() {
		t.Fatalf("recorded pid = %d found=%v, want %d", pid, found, os.Getpid())
	}
}

// A crash leaves lock files behind that block every later Git operation. The
// failure has to say that snailmail left them and which ones to remove,
// otherwise the operator only sees Git's opaque "File exists".
func TestGitLockConflictExplainsAbandonedLock(t *testing.T) {
	directory := t.TempDir()
	blocked := filepath.Join(directory, "index.lock")
	names := []string{blocked, filepath.Join(directory, "HEAD.lock")}

	withGitLockOwnerRunning(t, func(int) bool { return false })
	abandoned := gitLockOwnerPrefix + "\npid=4242\nsince=2026-01-01T00:00:00Z\n"
	if err := os.WriteFile(blocked, []byte(abandoned), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := acquireGitLock(blocked)
	if err == nil {
		t.Fatal("expected acquiring an existing lock to fail")
	}
	message := describeGitLockConflict(blocked, names, err).Error()
	for _, want := range []string{"snailmail", "remove", blocked, names[1]} {
		if !strings.Contains(message, want) {
			t.Fatalf("message %q does not mention %q", message, want)
		}
	}
}

func TestGitLockConflictDoesNotClaimForeignLocks(t *testing.T) {
	directory := t.TempDir()
	blocked := filepath.Join(directory, "index.lock")
	if err := os.WriteFile(blocked, []byte("some other git process"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := acquireGitLock(blocked)
	if err == nil {
		t.Fatal("expected acquiring an existing lock to fail")
	}
	message := describeGitLockConflict(blocked, []string{blocked}, err).Error()
	if strings.Contains(message, "remove") {
		t.Fatalf("a lock snailmail does not own must not be recommended for removal: %q", message)
	}
	if !strings.Contains(message, "another Git process") {
		t.Fatalf("message %q does not attribute the lock to Git", message)
	}
}
