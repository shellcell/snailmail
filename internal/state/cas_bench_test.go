package state

import (
	"github.com/shellcell/snailmail/formats"
	"testing"

	"github.com/shellcell/snailmail/internal/factscache"
	"github.com/shellcell/snailmail/internal/testutil"
)

// A single apply validates the same artifact several times: once assembling
// the build input and again for each verification pass over the staged tree.
//
// The synthetic package here is small, so this understates the effect on real
// packages: the memoised step decompresses a Debian data archive in full, up
// to 256 MiB, purely to total the installed size.
func BenchmarkRepeatedBlobValidation(b *testing.B) {
	root := b.TempDir()
	source, err := testutil.WriteDeb(b.TempDir(), "snail-demo", "1.2.3", "amd64", nil)
	if err != nil {
		b.Fatal(err)
	}
	blob, err := PutArtifact(root, "deb", source, formats.Identity{})
	if err != nil {
		b.Fatal(err)
	}
	locked := ToLockedBlob(blob)
	b.ReportAllocs()
	for b.Loop() {
		factscache.Reset()
		// Four validations, as one apply performs.
		for range 4 {
			if _, _, err := LoadBlob(root, "deb", locked, formats.Identity{}); err != nil {
				b.Fatal(err)
			}
		}
	}
}
