package host

import (
	"slices"
	"testing"
)

// A symlink rename makes a whole tree live at once, so the number of paths that
// have to switch together does not matter — which is what an object store cannot
// say, since it commits one object atomically and no more.
//
// The consequence worth pinning: rsync is the only host that serves every format,
// including a signed yum repository, whose repomd.xml and repomd.xml.asc must
// become live together. If a format is ever added and this host is not extended,
// this fails and says which.
func TestRsyncServesEveryFormat(t *testing.T) {
	every := []string{"apk", "deb", "helm", "pypi", "raw", "rpm"}
	served := SupportedFormats("rsync")
	if !slices.Equal(served, every) {
		t.Errorf("rsync serves %v, want every format %v", served, every)
	}
	// The contrast that makes the claim mean something. An object store cannot
	// serve a signed yum repository, and it is the commit-path count that stops it
	// rather than a rule stated twice.
	if slices.Contains(SupportedFormats("s3"), "deb") {
		t.Error("the object store now claims Debian, so the reasoning above is stale")
	}
}
