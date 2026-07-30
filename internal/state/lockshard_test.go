package state

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func shardingRepository() Repository { return Repository{Lock: "repos/apt.lock.toml"} }

func lockOf(versions int) RepositoryLock {
	lock := RepositoryLock{SchemaVersion: LockSchema, Repository: "apt"}
	for index := range versions {
		lock.PackageVersion = append(lock.PackageVersion, PackageVersion{
			Package: fmt.Sprintf("package-%05d", index),
			Version: "1.0.0",
			State:   "draft",
			Blobs: []LockedBlob{{
				Filename: fmt.Sprintf("package-%05d_1.0.0_amd64.deb", index),
				SHA256:   "add4eb51b88b3d944acafb66aead0bc33537595397f15be287d25504ec1dbeb8",
				Size:     1234567, Architecture: "amd64",
			}},
		})
	}
	return lock
}

func workspaceWithRepos(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "repos"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

// A repository small enough stays one file. That is every repository today, and a
// layout change nobody asked for would be a diff rewriting everything.
func TestASmallLockStaysOneFile(t *testing.T) {
	root := workspaceWithRepos(t)
	if err := WriteLock(root, shardingRepository(), lockOf(10)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "repos", "apt.lock.d")); !os.IsNotExist(err) {
		t.Error("a small lock was sharded")
	}
	loaded, err := LoadLock(root, shardingRepository())
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.PackageVersion) != 10 {
		t.Errorf("loaded %d versions", len(loaded.PackageVersion))
	}
}

// Past the threshold the lock becomes a root plus one file per package, and reading
// it back gives exactly what was written.
func TestALargeLockShardsAndRoundTrips(t *testing.T) {
	root := workspaceWithRepos(t)
	written := lockOf(LockShardThreshold + 500)
	if err := WriteLock(root, shardingRepository(), written); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "repos", "apt.lock.d")
	if _, err := os.Stat(directory); err != nil {
		t.Fatalf("a lock past the threshold was not sharded: %v", err)
	}
	loaded, err := LoadLock(root, shardingRepository())
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.PackageVersion) != len(written.PackageVersion) {
		t.Fatalf("wrote %d versions and read back %d", len(written.PackageVersion), len(loaded.PackageVersion))
	}
	byName := make(map[string]PackageVersion, len(loaded.PackageVersion))
	for _, packageVersion := range loaded.PackageVersion {
		byName[packageVersion.Package] = packageVersion
	}
	for _, original := range written.PackageVersion {
		round, found := byName[original.Package]
		if !found {
			t.Fatalf("%s is missing after a round trip", original.Package)
		}
		if len(round.Blobs) != 1 || round.Blobs[0].SHA256 != original.Blobs[0].SHA256 {
			t.Fatalf("%s came back as %+v", original.Package, round)
		}
	}
	// The root alone says what the lock contains, so a reader knows what is missing
	// rather than what happened to be on disk.
	rootContent, err := os.ReadFile(filepath.Join(root, "repos", "apt.lock.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rootContent), "merkle_root") {
		t.Error("the root does not carry a Merkle root")
	}
}

// This is the reason the layout exists. Adding one version to a large repository
// must rewrite one small file, not all of them — otherwise every publication is a
// whole-repository diff and review does not scale.
func TestAddingOneVersionRewritesOneFile(t *testing.T) {
	root := workspaceWithRepos(t)
	lock := lockOf(LockShardThreshold + 500)
	if err := WriteLock(root, shardingRepository(), lock); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "repos", "apt.lock.d")
	before := shardModificationTimes(t, directory)

	// Backdate everything so a rewrite is visible as a changed mtime.
	stale := time.Now().Add(-time.Hour)
	for name := range before {
		if err := os.Chtimes(name, stale, stale); err != nil {
			t.Fatal(err)
		}
	}
	before = shardModificationTimes(t, directory)

	lock.PackageVersion = append(lock.PackageVersion, PackageVersion{
		Package: "package-00007", Version: "2.0.0", State: "draft",
		Blobs: []LockedBlob{{
			Filename: "package-00007_2.0.0_amd64.deb", Architecture: "amd64", Size: 42,
			SHA256: "4a5a4e68281b9fd6d5291766633fba25e52ccfa47214cf152ac9fafd0ca621bc",
		}},
	})
	if err := WriteLock(root, shardingRepository(), lock); err != nil {
		t.Fatal(err)
	}
	after := shardModificationTimes(t, directory)

	var rewritten []string
	for name, when := range after {
		if !before[name].Equal(when) {
			rewritten = append(rewritten, filepath.Base(name))
		}
	}
	if len(rewritten) != 1 {
		t.Errorf("adding one version rewrote %d shards (%v), want 1", len(rewritten), rewritten)
	}
	if len(rewritten) == 1 && !strings.Contains(rewritten[0], "package-00007") {
		t.Errorf("the rewritten shard is %q, want the package that changed", rewritten[0])
	}
}

func shardModificationTimes(t *testing.T, directory string) map[string]time.Time {
	t.Helper()
	times := make(map[string]time.Time)
	err := filepath.Walk(directory, func(name string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(name, ".toml") {
			times[name] = info.ModTime()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return times
}

// A lock is the record a publication is verified against, so a shard edited on its
// own has to be an error rather than a quietly different repository.
func TestAnEditedShardIsRefused(t *testing.T) {
	root := workspaceWithRepos(t)
	if err := WriteLock(root, shardingRepository(), lockOf(LockShardThreshold+1)); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "repos", "apt.lock.d")
	var edited string
	for name := range shardModificationTimes(t, directory) {
		edited = name
		break
	}
	content, err := os.ReadFile(edited)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(content),
		"add4eb51b88b3d944acafb66aead0bc33537595397f15be287d25504ec1dbeb8",
		"0000000000000000000000000000000000000000000000000000000000000000", 1)
	if err := os.WriteFile(edited, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = LoadLock(root, shardingRepository())
	if err == nil {
		t.Fatal("a lock with an edited shard was loaded")
	}
	if !strings.Contains(err.Error(), "digest") {
		t.Errorf("error = %v, want the digest mismatch named", err)
	}
}

// Removing a package from the index without the root changing would be a lock that
// quietly serves less than it says, so the Merkle root covers which shards exist
// and not only what each contains.
func TestRemovingAShardFromTheIndexIsRefused(t *testing.T) {
	root := workspaceWithRepos(t)
	if err := WriteLock(root, shardingRepository(), lockOf(LockShardThreshold+1)); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(root, "repos", "apt.lock.toml")
	content, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	// Drop one [[shard]] block, leaving the Merkle root claiming the full set.
	start := strings.Index(string(content), "[[shard]]")
	end := strings.Index(string(content)[start+1:], "[[shard]]")
	if start < 0 || end < 0 {
		t.Fatal("could not find two shard entries to edit")
	}
	trimmed := string(content)[:start] + string(content)[start+1+end:]
	if err := os.WriteFile(name, []byte(trimmed), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = LoadLock(root, shardingRepository())
	if err == nil {
		t.Fatal("a root whose index no longer matches its Merkle root was loaded")
	}
	if !strings.Contains(err.Error(), "Merkle") {
		t.Errorf("error = %v, want the Merkle root named", err)
	}
}

// A package dropped from the lock has its file removed, so the directory says the
// same thing the root does.
func TestARemovedPackageLosesItsShard(t *testing.T) {
	root := workspaceWithRepos(t)
	lock := lockOf(LockShardThreshold + 500)
	if err := WriteLock(root, shardingRepository(), lock); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "repos", "apt.lock.d")
	before := len(shardModificationTimes(t, directory))

	lock.PackageVersion = lock.PackageVersion[:len(lock.PackageVersion)-1]
	if err := WriteLock(root, shardingRepository(), lock); err != nil {
		t.Fatal(err)
	}
	if after := len(shardModificationTimes(t, directory)); after != before-1 {
		t.Errorf("shards went from %d to %d after dropping one package", before, after)
	}
	loaded, err := LoadLock(root, shardingRepository())
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.PackageVersion) != len(lock.PackageVersion) {
		t.Errorf("loaded %d versions, want %d", len(loaded.PackageVersion), len(lock.PackageVersion))
	}
}

// Two packages differing only in case are two packages. On a case-insensitive
// filesystem a name-only path would give them one file, which is a silent wrong
// answer rather than an error — so the digest is in the path.
func TestPackagesDifferingOnlyInCaseGetTheirOwnShards(t *testing.T) {
	if shardRelativePath("Django") == shardRelativePath("django") {
		t.Error("two packages differing only in case share a shard path")
	}
	// And the readable part survives, or a directory listing and a diff are
	// unreadable.
	if !strings.Contains(shardRelativePath("django"), "django") {
		t.Errorf("shard path %q does not name its package", shardRelativePath("django"))
	}
}

// A path in the index that leaves the lock directory would make loading a lock
// read arbitrary files.
func TestAShardPathCannotLeaveTheLockDirectory(t *testing.T) {
	root := workspaceWithRepos(t)
	if err := WriteLock(root, shardingRepository(), lockOf(LockShardThreshold+1)); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(root, "repos", "apt.lock.toml")
	content, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	escaped := strings.Replace(string(content), "path = '", "path = '../../../etc/", 1)
	if err := os.WriteFile(name, []byte(escaped), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLock(root, shardingRepository()); err == nil {
		t.Fatal("a shard path leaving the lock directory was followed")
	}
}
