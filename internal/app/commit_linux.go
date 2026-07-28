//go:build linux

package app

import "golang.org/x/sys/unix"

// exchangePaths swaps two directory entries in one atomic step.
func exchangePaths(from, to string) error {
	return unix.Renameat2(unix.AT_FDCWD, from, unix.AT_FDCWD, to, unix.RENAME_EXCHANGE)
}
