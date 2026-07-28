package app

import (
	"fmt"
	"os"
)

// exchangeReleaseLink atomically swaps output with the temporary symlink,
// leaving the displaced entry at temporary. Reading back what was displaced is
// what makes the switch a compare-and-swap rather than a lost update: a
// concurrent writer's release survives at temporary and is reported instead of
// being silently overwritten.
func exchangeReleaseLink(temporary, output, expectedLink string) (bool, error) {
	if err := exchangePaths(temporary, output); err != nil {
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
