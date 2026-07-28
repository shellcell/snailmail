package deb

import (
	"fmt"
	"testing"
	"time"

	"github.com/shellcell/snailmail/internal/domain"
)

// BenchmarkBuildPackagesIndex guards the memory cost of rendering a large
// Packages index, which is the largest allocation in a Debian build.
func BenchmarkBuildPackagesIndex(b *testing.B) {
	blobs := make([]domain.Blob, 0, 2000)
	for i := 0; i < 2000; i++ {
		name := fmt.Sprintf("pkg%04d", i)
		blobs = append(blobs, domain.Blob{
			Filename: name + "_1.0.0_amd64.deb", Size: 1024,
			MD5:    "0123456789abcdef0123456789abcdef",
			SHA1:   "0123456789abcdef0123456789abcdef01234567",
			SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Facts: domain.PackageFacts{Name: name, Version: "1.0.0", Architecture: "amd64", Fields: map[string]string{
				"Package": name, "Version": "1.0.0", "Architecture": "amd64",
				"Description": "a package\nwith a long multi-line description\n.\nand more text to make the stanza realistic",
				"Maintainer":  "Someone <someone@example.invalid>", "Depends": "libc6, libssl3, zlib1g",
			}},
		})
	}
	options := BuildOptions{Suite: "stable", Component: "main", Architectures: []string{"amd64"}, GeneratedAt: time.Unix(0, 0).UTC()}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Build(blobs, options); err != nil {
			b.Fatal(err)
		}
	}
}
