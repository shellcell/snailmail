package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The limit exists so that a workspace past the envelope meets a sentence instead
// of the OOM killer. So the message has to carry everything needed to act: which
// repository, how large, the limit, and what to do about it.
func TestTheLimitMessageSaysWhatToDo(t *testing.T) {
	err := requireLockWithinLimit("repos/apt.lock.toml", 200<<20)
	if err == nil {
		t.Fatal("a 200 MiB lock was accepted under a 128 MiB limit")
	}
	message := err.Error()
	for _, want := range []string{
		"repos/apt.lock.toml", // which repository
		"200 MiB",             // how large it is
		"128 MiB",             // the limit it passed
		"prune",               // a remedy
		"split",               // the other remedy
		MaxLockBytesEnvironment,
	} {
		if !strings.Contains(message, want) {
			t.Errorf("message does not mention %q: %s", want, message)
		}
	}
}

// A lock at the limit is within it. Off-by-one here would refuse a workspace that
// was told it had room.
func TestALockAtTheLimitIsAccepted(t *testing.T) {
	if err := requireLockWithinLimit("x", DefaultMaxLockBytes); err != nil {
		t.Errorf("a lock exactly at the limit was refused: %v", err)
	}
	if err := requireLockWithinLimit("x", DefaultMaxLockBytes+1); err == nil {
		t.Error("a lock one byte over the limit was accepted")
	}
}

// The override is an operational escape hatch, so it has to work — and a typo in
// it must not silently refuse every lock in the workspace, which would be a worse
// failure than the one the limit prevents.
func TestTheOverrideRaisesTheLimitAndIgnoresNonsense(t *testing.T) {
	t.Setenv(MaxLockBytesEnvironment, "1048576")
	if err := requireLockWithinLimit("x", 2<<20); err == nil {
		t.Error("a lowered limit was not applied")
	}
	if !strings.Contains(requireLockWithinLimit("x", 2<<20).Error(), "1 MiB") {
		t.Error("the message reports the default rather than the override in force")
	}
	for _, nonsense := range []string{"lots", "-1", "0", "12MB", " "} {
		t.Setenv(MaxLockBytesEnvironment, nonsense)
		if err := requireLockWithinLimit("x", DefaultMaxLockBytes/2); err != nil {
			t.Errorf("%q made an ordinary lock fail: %v", nonsense, err)
		}
		if err := requireLockWithinLimit("x", DefaultMaxLockBytes*2); err == nil {
			t.Errorf("%q disabled the limit entirely", nonsense)
		}
	}
}

// Enforced where a lock is actually read, so every path gets it — plan, apply,
// status and check all go through LoadLock.
func TestLoadLockRefusesAnOversizedLockBeforeParsingIt(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "repos"), 0o755); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(root, "repos", "big.lock.toml")
	// Deliberately not valid TOML: if the limit is checked first, the error names
	// the size rather than a parse failure. That ordering is the point.
	if err := os.WriteFile(name, []byte(strings.Repeat("x", 4096)), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(MaxLockBytesEnvironment, "1024")
	_, err := LoadLock(root, Repository{Lock: "repos/big.lock.toml"})
	if err == nil {
		t.Fatal("an oversized lock was loaded")
	}
	if !strings.Contains(err.Error(), "over the") {
		t.Errorf("error = %v, want the size limit rather than a parse failure", err)
	}
}

// A lock within the limit still loads, which is the case every existing workspace
// is in and the one a limit must not break.
func TestAnOrdinaryLockIsUnaffected(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "repos"), 0o755); err != nil {
		t.Fatal(err)
	}
	lock := RepositoryLock{SchemaVersion: LockSchema, Repository: "apt"}
	if err := WriteLock(root, Repository{Lock: "repos/apt.lock.toml"}, lock); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadLock(root, Repository{Lock: "repos/apt.lock.toml"})
	if err != nil {
		t.Fatalf("an ordinary lock was refused: %v", err)
	}
	if loaded.Repository != "apt" {
		t.Errorf("loaded %+v", loaded)
	}
}
