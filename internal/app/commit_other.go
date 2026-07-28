//go:build !linux && !darwin

package app

import "errors"

// exchangePaths needs an atomic directory-entry exchange. Linux provides it
// through renameat2(RENAME_EXCHANGE) and darwin through
// renamex_np(RENAME_SWAP); platforms without either cannot replace an existing
// managed release without risking a lost update. Creating a first managed
// release stays portable.
func exchangePaths(_, _ string) error {
	return errors.New("atomic managed-release replacement is not implemented on this platform")
}
