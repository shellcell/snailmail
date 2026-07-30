package state

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/pelletier/go-toml/v2"
)

// A lock large enough to be a problem is split into one file per package, under a
// root that names them and a Merkle digest over the set.
//
// Measured at 385 bytes per package-version, a whole-file lock is 38.5 MB at
// 100,000 versions and around 385 MB at a million. Parse time and heap follow, but
// they are not the binding constraint: a monolithic file of that size in version
// control is, because every publication rewrites all of it and every review diffs
// all of it. Sharding fixes that directly — adding one version rewrites one small
// file, and a reviewer sees the package that changed rather than a 38 MB diff.
//
// The set still has one identity. The root records a digest per shard and a Merkle
// root over them, so what a plan pins and a ledger records is unchanged in kind: a
// single value that fixes the whole lock. A shard edited without the root failing
// to match is the case this exists to prevent.
//
// The layout sits beside the existing lock rather than replacing its path, so a
// repository configured before this existed keeps working with no migration and
// Repository.Lock still names the file to read first:
//
//	repos/apt.lock.toml     the root: schema, placement, and the shard index
//	repos/apt.lock.d/3f/…   one file per package
const (
	// LockShardSchema marks a root whose packages live in shards. A whole-file
	// lock stays at LockSchema, so an existing workspace is untouched until it
	// grows past the threshold.
	LockShardSchema = 3

	// LockShardThreshold is the package-version count above which a lock is
	// written as shards.
	//
	// Deliberately a count rather than a byte size, so the layout of a lock is a
	// function of what is in it rather than of how it happened to encode — a
	// repository does not flip between layouts because an origin URL got longer.
	// Two thousand versions is about 0.8 MB, which is comfortably reviewable as
	// one file; past that the diffs are the problem before the parse is.
	LockShardThreshold = 2000
)

// lockRoot is what the lock path holds once a repository is sharded. It carries
// everything about the lock except the packages themselves.
type lockRoot struct {
	SchemaVersion int         `toml:"schema_version"`
	Repository    string      `toml:"repository"`
	Placement     []Placement `toml:"placement"`
	// MerkleRoot fixes the whole package set. A shard changed without it changing
	// is a lock that no longer says what it says.
	MerkleRoot string `toml:"merkle_root"`
	// Shard is the index, sorted by package, so the root alone says what the lock
	// contains and a reader knows what is missing rather than what it happened to
	// find on disk.
	Shard []lockShardEntry `toml:"shard"`
}

type lockShardEntry struct {
	Package string `toml:"package"`
	Path    string `toml:"path"`
	SHA256  string `toml:"sha256"`
}

// lockShard is one package's file.
type lockShard struct {
	Package        string           `toml:"package"`
	PackageVersion []PackageVersion `toml:"package_version"`
}

// shardDirectory is where a lock's shards live, derived from its own path so the
// two cannot drift apart.
func shardDirectory(lockPath string) string {
	return strings.TrimSuffix(lockPath, filepath.Ext(lockPath)) + ".d"
}

// shardRelativePath names one package's file.
//
// The digest makes it unique; the slug makes it readable. Both are needed: a bare
// name would collide on a case-insensitive filesystem for two packages differing
// only in case, which is a silent wrong answer rather than an error, and a bare
// digest would make a directory listing and a diff unreadable.
func shardRelativePath(packageName string) string {
	sum := sha256.Sum256([]byte(packageName))
	digest := hex.EncodeToString(sum[:])
	slug := shardSlug(packageName)
	if slug == "" {
		return filepath.ToSlash(filepath.Join(digest[:2], digest[:12]+".toml"))
	}
	return filepath.ToSlash(filepath.Join(digest[:2], slug+"-"+digest[:12]+".toml"))
}

func shardSlug(packageName string) string {
	var slug strings.Builder
	for _, letter := range strings.ToLower(packageName) {
		switch {
		case letter >= 'a' && letter <= 'z', letter >= '0' && letter <= '9':
			slug.WriteRune(letter)
		case letter == '-' || letter == '_' || letter == '.' || letter == '+':
			slug.WriteRune('-')
		}
		if slug.Len() >= 48 {
			break
		}
	}
	return strings.Trim(slug.String(), "-")
}

// merkleRoot digests the shard index.
//
// Over the sorted package names and their file digests, so it fixes both what each
// shard contains and which shards exist. Digesting only the contents would let a
// whole package be removed without the root changing, which is the failure worth
// designing against — a lock that quietly serves less than it says.
func merkleRoot(entries []lockShardEntry) string {
	sorted := append([]lockShardEntry(nil), entries...)
	sort.Slice(sorted, func(left, right int) bool { return sorted[left].Package < sorted[right].Package })
	hash := sha256.New()
	for _, entry := range sorted {
		fmt.Fprintf(hash, "%s\x00%s\x00%s\n", entry.Package, entry.Path, entry.SHA256)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// shouldShard reports whether a lock is written as shards.
//
// Either it is already, or it has grown past the threshold. A lock never goes back
// to one file on its own: a repository that shrank below the threshold would
// otherwise produce a diff rewriting everything, which is exactly what sharding
// exists to avoid.
func shouldShard(lockPath string, lock RepositoryLock) bool {
	if len(lock.PackageVersion) > LockShardThreshold {
		return true
	}
	_, err := os.Stat(shardDirectory(lockPath))
	return err == nil
}

// writeShardedLock writes the root and one file per package, and removes shards for
// packages that are gone.
//
// Only changed shards are rewritten. That is the point of the layout rather than an
// optimisation: an unchanged file has an unchanged mtime and produces no diff, so
// adding one version to a repository of ten thousand packages is a one-file change
// in review.
func writeShardedLock(lockPath string, lock RepositoryLock) error {
	directory := shardDirectory(lockPath)
	byPackage := make(map[string][]PackageVersion)
	for _, packageVersion := range lock.PackageVersion {
		byPackage[packageVersion.Package] = append(byPackage[packageVersion.Package], packageVersion)
	}
	entries := make([]lockShardEntry, 0, len(byPackage))
	written := make(map[string]bool, len(byPackage))
	created := make(map[string]bool, 256)
	// The digests the previous root recorded, so an unchanged package is settled by
	// comparing two strings rather than by reading its file back. Without this every
	// write reads the whole lock, which is the cost sharding exists to remove.
	previous := previousShardDigests(lockPath)
	var changed []string
	for packageName, versions := range byPackage {
		relative := shardRelativePath(packageName)
		encoded, err := toml.Marshal(lockShard{Package: packageName, PackageVersion: versions})
		if err != nil {
			return fmt.Errorf("encode lock shard for %q: %w", packageName, err)
		}
		name := filepath.Join(directory, filepath.FromSlash(relative))
		parent := filepath.Dir(name)
		if !created[parent] {
			if err := os.MkdirAll(parent, 0o755); err != nil {
				return fmt.Errorf("create lock shard directory: %w", err)
			}
			created[parent] = true
		}
		sum := sha256.Sum256(encoded)
		digest := hex.EncodeToString(sum[:])
		// Compared before writing, so an unchanged package is not rewritten and does
		// not appear in a diff.
		if previous[relative] != digest {
			if err := writeShardFile(name, encoded); err != nil {
				return err
			}
			changed = append(changed, name)
		}
		entries = append(entries, lockShardEntry{
			Package: packageName, Path: relative, SHA256: digest,
		})
		written[relative] = true
	}
	if err := removeStaleShards(directory, written); err != nil {
		return err
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Package < entries[right].Package })
	root := lockRoot{
		SchemaVersion: LockShardSchema, Repository: lock.Repository,
		Placement: lock.Placement, MerkleRoot: merkleRoot(entries), Shard: entries,
	}
	encoded, err := toml.Marshal(root)
	if err != nil {
		return fmt.Errorf("encode lock root: %w", err)
	}
	// The shards are made durable once, here, rather than each on its own. Syncing
	// every file costs several fsyncs per package and dominates the write —
	// measured at roughly 5 ms per shard, which is thirteen seconds for 2,500
	// packages and minutes for a hundred thousand.
	//
	// What makes one sync sufficient is that the root is the only thing that
	// declares a shard valid, and it is written last and atomically. A crash before
	// that leaves the previous root beside a shard it no longer digests, which
	// LoadLock refuses by name rather than accepting quietly — and the lock is a
	// tracked file, so the recovery is git checkout rather than a repair tool. A
	// loud, recoverable failure in a window that requires a crash is the right trade
	// for a write that stays usable at scale.
	if err := syncPaths(changed); err != nil {
		return err
	}
	return atomicWrite(lockPath, encoded, 0o644)
}

// writeShardFile replaces one shard by rename, without syncing it. Durability for
// the set is established once, before the root is written.
func writeShardFile(name string, content []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(name), ".snailmail-shard-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, name)
}

// syncPaths flushes the shards that were actually written, and the directories
// holding them, so they are on disk before the root that vouches for them.
//
// Only what changed: syncing every shard on every write is proportional to the
// repository rather than to the change, which is the cost this layout exists to
// avoid.
func syncPaths(names []string) error {
	directories := make(map[string]bool, len(names))
	for _, name := range names {
		if err := syncPath(name); err != nil {
			return err
		}
		directories[filepath.Dir(name)] = true
	}
	for directory := range directories {
		if err := syncPath(directory); err != nil {
			return err
		}
	}
	return nil
}

func syncPath(name string) error {
	handle, err := os.Open(name)
	if err != nil {
		return err
	}
	syncErr := handle.Sync()
	closeErr := handle.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

// previousShardDigests reads the digests the current root records, or nothing if
// there is no readable root yet — in which case every shard is written, which is
// correct for a first write.
func previousShardDigests(lockPath string) map[string]string {
	content, err := os.ReadFile(lockPath)
	if err != nil {
		return nil
	}
	root, sharded := looksSharded(content)
	if !sharded {
		return nil
	}
	digests := make(map[string]string, len(root.Shard))
	for _, entry := range root.Shard {
		digests[entry.Path] = entry.SHA256
	}
	return digests
}

// removeStaleShards deletes files for packages the lock no longer holds, so the
// directory says the same thing the root does.
func removeStaleShards(directory string, keep map[string]bool) error {
	return filepath.Walk(directory, func(name string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.IsDir() || !strings.HasSuffix(name, ".toml") {
			return nil
		}
		relative, relErr := filepath.Rel(directory, name)
		if relErr != nil {
			return relErr
		}
		if keep[filepath.ToSlash(relative)] {
			return nil
		}
		return os.Remove(name)
	})
}

// readShardedLock reassembles a lock from its root and shards.
//
// Every shard is checked against the digest the root states for it, and the root's
// own Merkle value is recomputed from the index. A lock is the record a publication
// is verified against, so a shard edited on its own has to be an error rather than
// a quietly different repository.
func readShardedLock(lockPath string, root lockRoot, lockName string) (RepositoryLock, error) {
	directory := shardDirectory(lockPath)
	lock := RepositoryLock{
		SchemaVersion: LockSchema, Repository: root.Repository, Placement: root.Placement,
	}
	if recomputed := merkleRoot(root.Shard); recomputed != root.MerkleRoot {
		return RepositoryLock{}, fmt.Errorf(
			"lock %s: the shard index does not match its Merkle root, so the lock has been edited in part", lockName)
	}
	for _, entry := range root.Shard {
		if strings.Contains(entry.Path, "..") || strings.HasPrefix(entry.Path, "/") {
			return RepositoryLock{}, fmt.Errorf("lock %s: shard path %q leaves the lock directory", lockName, entry.Path)
		}
	}
	// Read in parallel. One file per package turns a single large parse into
	// thousands of small independent ones, which is the cost of this layout and the
	// one thing about it that is worse than a whole file; they do not depend on each
	// other, so the cores are there to be used. Results are placed by index rather
	// than appended, so the order is the root's and does not vary run to run.
	workers := runtime.GOMAXPROCS(0)
	if workers > len(root.Shard) {
		workers = len(root.Shard)
	}
	if workers < 1 {
		workers = 1
	}
	parsed := make([][]PackageVersion, len(root.Shard))
	sizes := make([]int64, len(root.Shard))
	errs := make([]error, len(root.Shard))
	next := make(chan int)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range next {
				entry := root.Shard[index]
				name := filepath.Join(directory, filepath.FromSlash(entry.Path))
				content, err := os.ReadFile(name)
				if err != nil {
					errs[index] = fmt.Errorf("lock %s: shard for %q: %w", lockName, entry.Package, err)
					continue
				}
				sizes[index] = int64(len(content))
				sum := sha256.Sum256(content)
				if hex.EncodeToString(sum[:]) != entry.SHA256 {
					errs[index] = fmt.Errorf(
						"lock %s: shard for %q does not match the digest the root states for it", lockName, entry.Package)
					continue
				}
				var shard lockShard
				if err := toml.Unmarshal(content, &shard); err != nil {
					errs[index] = fmt.Errorf("lock %s: decode shard for %q: %w", lockName, entry.Package, err)
					continue
				}
				if shard.Package != entry.Package {
					errs[index] = fmt.Errorf(
						"lock %s: the shard indexed as %q holds package %q", lockName, entry.Package, shard.Package)
					continue
				}
				parsed[index] = shard.PackageVersion
			}
		}()
	}
	for index := range root.Shard {
		next <- index
	}
	close(next)
	group.Wait()

	// The first failure in the root's order, so the same broken lock reports the
	// same shard every time rather than whichever worker lost a race.
	var total int64
	for index := range root.Shard {
		if errs[index] != nil {
			return RepositoryLock{}, errs[index]
		}
		total += sizes[index]
		if err := requireLockWithinLimit(lockName, total); err != nil {
			return RepositoryLock{}, err
		}
		lock.PackageVersion = append(lock.PackageVersion, parsed[index]...)
	}
	return lock, nil
}

// looksSharded reports whether the file at a lock path is a sharded root.
func looksSharded(content []byte) (lockRoot, bool) {
	var root lockRoot
	if err := toml.Unmarshal(content, &root); err != nil {
		return lockRoot{}, false
	}
	return root, root.SchemaVersion == LockShardSchema
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
