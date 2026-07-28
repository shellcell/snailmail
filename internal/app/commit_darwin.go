//go:build darwin

package app

import "golang.org/x/sys/unix"

// exchangePaths swaps two directory entries in one atomic step. RENAME_SWAP is
// the darwin equivalent of Linux's RENAME_EXCHANGE.
func exchangePaths(from, to string) error {
	return unix.RenamexNp(from, to, unix.RENAME_SWAP)
}
