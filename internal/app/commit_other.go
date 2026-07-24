//go:build !linux

package app

import (
	"fmt"
	"os"
)

func commitReleaseLink(temporary, output, expectedLink string) (bool, error) {
	if expectedLink != "" {
		return false, fmt.Errorf("atomic managed-release replacement is not implemented on this platform")
	}
	if err := os.Link(temporary, output); err != nil {
		return false, err
	}
	return true, nil
}
