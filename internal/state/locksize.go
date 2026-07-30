package state

import (
	"fmt"
	"os"
	"strconv"
)

// DefaultMaxLockBytes bounds a repository lock.
//
// A lock is parsed whole on every plan, apply, status and check, so its size sets
// both how long those take and how much memory they need. Measured at roughly 385
// bytes per package-version, and parsing costs about one and a half times the file
// in heap:
//
//	  2,000 versions     0.8 MB       5 ms      1 MB
//	 20,000 versions      7.7 MB      44 ms     12 MB
//	100,000 versions     38.5 MB     226 ms     59 MB
//
// This limit is about 330,000 package-versions — far past any workspace that
// exists today, and low enough that a runaway is caught while the failure is still
// a sentence rather than the OOM killer.
//
// The point is not to prevent large repositories. It is that a workspace which has
// outgrown a single lock should be told so, with the number and the remedy, instead
// of getting slower until something dies. Sharding the lock is the real answer and
// this is what makes its absence survivable.
const DefaultMaxLockBytes = 128 << 20

// MaxLockBytesEnvironment raises or lowers the limit for one invocation.
//
// An environment variable rather than a manifest field, deliberately: this is an
// operational escape hatch for someone who has read the message and decided to
// proceed, not a property of the workspace worth reviewing. A workspace that
// genuinely needs a larger limit needs sharding, not configuration.
const MaxLockBytesEnvironment = "SNAILMAIL_MAX_LOCK_BYTES"

// maxLockBytes is the limit in force. A value that is not a positive number is
// ignored rather than treated as zero, because a typo in an environment variable
// must not silently refuse every lock.
func maxLockBytes() int64 {
	given := os.Getenv(MaxLockBytesEnvironment)
	if given == "" {
		return DefaultMaxLockBytes
	}
	parsed, err := strconv.ParseInt(given, 10, 64)
	if err != nil || parsed <= 0 {
		return DefaultMaxLockBytes
	}
	return parsed
}

// requireLockWithinLimit refuses a lock too large to work with.
//
// Checked before parsing rather than after, which is the whole point: reading a
// 2 GB lock to discover it is too large has already done the damage.
func requireLockWithinLimit(repository string, size int64) error {
	limit := maxLockBytes()
	if size <= limit {
		return nil
	}
	return fmt.Errorf(
		"repository %q has a %s lock, over the %s limit, and parsing it needs roughly %s of memory "+
			"on every plan and apply: prune retained versions, split the repository, "+
			"or set %s to proceed anyway",
		repository, humanSize(size), humanSize(limit), humanSize(size*3/2), MaxLockBytesEnvironment)
}

// humanSize renders a size the way the message needs it: coarse enough to read,
// exact enough to compare against a limit.
func humanSize(bytes int64) string {
	switch {
	case bytes >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(bytes)/(1<<30))
	case bytes >= 1<<20:
		return fmt.Sprintf("%.0f MiB", float64(bytes)/(1<<20))
	case bytes >= 1<<10:
		return fmt.Sprintf("%.0f KiB", float64(bytes)/(1<<10))
	default:
		return fmt.Sprintf("%d bytes", bytes)
	}
}
