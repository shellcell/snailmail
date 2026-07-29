// Package hexdigest validates and converts the hex-encoded digests this
// project pins everything by.
//
// It exists because these predicates decide whether a digest is one the rest of
// the system may trust, and there were six copies of that decision — one per
// package that needed it, drifting quietly: five compared against
// sha256.Size and one against a literal 32. A rule that says what counts as a
// valid pin is exactly the kind that must have one definition.
package hexdigest

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// fingerprintSize is the length of an OpenPGP v4 fingerprint in bytes.
const fingerprintSize = 20

// ValidSHA256 reports whether a value is a lowercase hex SHA-256.
//
// Case matters: the same bytes written two ways would compare unequal
// everywhere digests are compared as strings, which is nearly everywhere.
func ValidSHA256(value string) bool {
	return validLowerHex(value, sha256.Size)
}

// ValidFingerprint reports whether a value is a lowercase hex OpenPGP v4 key
// fingerprint.
func ValidFingerprint(value string) bool {
	return validLowerHex(value, fingerprintSize)
}

func validLowerHex(value string, size int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == size && value == strings.ToLower(value)
}

// FromBase64 converts a base64 digest to lowercase hex, or returns empty for
// anything that is not base64.
//
// S3 reports checksums base64-encoded while everything here compares them as
// hex. Returning empty rather than an error is deliberate: the callers treat an
// unreadable checksum as an absent one, and an absent checksum already fails
// the comparison it was fetched for.
func FromBase64(value string) string {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(decoded)
}
