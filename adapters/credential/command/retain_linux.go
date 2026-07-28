//go:build linux

package commandcredential

import "os"

// retainSnapshot unlinks the hashed snapshot and returns the path that resolves
// to the retained inode. /proc/self/fd resolves to the open file itself, so the
// executed bytes remain exactly the hashed bytes even though no name refers to
// them any more.
func retainSnapshot(name string) (string, error) {
	if err := os.Remove(name); err != nil {
		return "", err
	}
	return "/proc/self/fd/3", nil
}
