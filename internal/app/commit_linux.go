//go:build linux

package app

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func commitReleaseLink(temporary, output, expectedLink string) (bool, error) {
	if expectedLink == "" {
		if err := unix.Renameat2(unix.AT_FDCWD, temporary, unix.AT_FDCWD, output, unix.RENAME_NOREPLACE); err != nil {
			return false, err
		}
		return true, nil
	}
	if err := unix.Renameat2(unix.AT_FDCWD, temporary, unix.AT_FDCWD, output, unix.RENAME_EXCHANGE); err != nil {
		return false, err
	}
	actualLink, readErr := os.Readlink(temporary)
	if readErr == nil && actualLink == expectedLink {
		return true, nil
	}
	if readErr != nil {
		return true, fmt.Errorf("entry changed concurrently and is preserved at %q: %w", temporary, readErr)
	}
	return true, fmt.Errorf("entry changed concurrently from %q to %q and is preserved at %q", expectedLink, actualLink, temporary)
}
