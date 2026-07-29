package app

import (
	"strings"
	"testing"
)

// Client verification exists to prove that the version the index advertises is
// the version a client actually installs. Asking a package manager for a bare
// name asks it for the newest one instead, so the check passes only while a
// repository holds exactly one version of each package and starts failing —
// against the wrong package — the moment a second is published.
//
// This is a text assertion because the scripts run inside a container against a
// real client, and the property worth protecting is that the request is pinned
// at all.
func TestClientVerificationInstallsThePinnedVersion(t *testing.T) {
	for name, script := range map[string]string{
		"apk": apkVerificationScript,
		"rpm": rpmVerificationScript,
	} {
		install := ""
		for _, line := range strings.Split(script, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			if strings.Contains(trimmed, "add ") || strings.Contains(trimmed, "install ") {
				install = trimmed
				break
			}
		}
		if install == "" {
			t.Fatalf("%s: no install command found in the verification script", name)
		}
		if !strings.Contains(install, "SNAILMAIL_VERSION") {
			t.Fatalf("%s: install request is not pinned to the version under verification: %q", name, install)
		}
	}
}
