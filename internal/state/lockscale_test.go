package state

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// A lock is one file per repository, read whole. This measures what that costs
// as placements grow, because the answer decides whether the file has to shard.
//
// Run it when considering that: go test ./internal/state/ -run XXX -bench LockScale
func BenchmarkLockScale(b *testing.B) {
	t := &scaleReporter{b}
	_ = t
	for _, versions := range []int{2000, 20000, 100000} {
		lock := RepositoryLock{SchemaVersion: 2, Repository: "scale"}
		for i := range versions {
			name := fmt.Sprintf("package-%04d", i%10000)
			lock.PackageVersion = append(lock.PackageVersion, PackageVersion{
				Package: name, Version: fmt.Sprintf("1.%d.0", i/10000), State: "published",
				Blobs: []LockedBlob{{
					Filename: name + "_1.0.0_amd64.deb", Architecture: "amd64", Size: 6071936,
					SHA256: fmt.Sprintf("%064x", i), Added: "2026-07-29T00:00:00Z",
					Origin: &ArtifactOrigin{Kind: "https", URL: "https://example.test/" + name},
				}},
			})
		}
		dir := b.TempDir()
		name := filepath.Join(dir, "scale.lock.toml")
		start := time.Now()
		encoded, err := toml.Marshal(lock)
		if err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(name, encoded, 0o644); err != nil {
			b.Fatal(err)
		}
		write := time.Since(start)
		info, _ := os.Stat(name)

		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start = time.Now()
		var loaded RepositoryLock
		err = decodeTOML(name, &loaded)
		if err != nil {
			b.Fatal(err)
		}
		read := time.Since(start)
		runtime.ReadMemStats(&after)

		b.Logf("%7d versions  file %6.1f MB  write %6.0fms  parse %6.0fms  heap +%4.0f MB",
			versions, float64(info.Size())/1e6, float64(write.Milliseconds()),
			float64(read.Milliseconds()),
			float64(after.HeapAlloc-before.HeapAlloc)/1e6)
	}
}

// scaleReporter exists only so the loop above reads the same whether it is run
// as a benchmark or, while investigating, as a test.
type scaleReporter struct{ b *testing.B }
