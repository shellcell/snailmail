//go:build !linux

package commandcredential

// retainSnapshot keeps the hashed snapshot linked and executes it by path.
// Outside Linux, /dev/fd reopens by path rather than resolving to the open
// file, so an unlinked snapshot cannot be executed at all. The snapshot already
// lives in a private 0700 directory with mode 0500, so no other user can reach
// or rewrite it, and the configured helper path is never consulted again —
// which is what keeps the executed bytes equal to the hashed bytes.
func retainSnapshot(name string) (string, error) {
	return name, nil
}
