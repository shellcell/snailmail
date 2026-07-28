package raw

import (
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// CompareVersions orders raw versions by SemVer where both sides parse, and by
// numeric natural order otherwise.
//
// Raw exists for artifacts no ecosystem governs, and real projects ship date
// schemes and four-component versions that SemVer rejects. Refusing them would
// push exactly the artifacts raw is for back out of the tool. The cost is that
// ordering between two different schemes in one package is defined but not
// obvious, so a package that mixes them sorts in a way worth looking at twice:
// SemVer versions order below anything that only parses numerically, because
// otherwise 1.0.0 and 20240115 would have no stable relation at all.
func CompareVersions(left, right string) (int, error) {
	leftSemver, leftErr := semver.NewVersion(left)
	rightSemver, rightErr := semver.NewVersion(right)
	if leftErr == nil && rightErr == nil {
		return leftSemver.Compare(rightSemver), nil
	}
	if leftErr == nil {
		return -1, nil
	}
	if rightErr == nil {
		return 1, nil
	}
	return compareNatural(left, right), nil
}

// compareNatural compares dot- and dash-separated segments, numerically when
// both segments are numeric so 1.2.3.10 sorts above 1.2.3.4, and lexically
// otherwise.
func compareNatural(left, right string) int {
	leftFields, rightFields := splitVersion(left), splitVersion(right)
	for index := 0; index < len(leftFields) || index < len(rightFields); index++ {
		leftField, rightField := "", ""
		if index < len(leftFields) {
			leftField = leftFields[index]
		}
		if index < len(rightFields) {
			rightField = rightFields[index]
		}
		// A missing segment is lower, so 1.2 sorts below 1.2.1.
		if leftField == "" {
			return -1
		}
		if rightField == "" {
			return 1
		}
		leftNumber, leftNumeric := strconv.ParseUint(leftField, 10, 64)
		rightNumber, rightNumeric := strconv.ParseUint(rightField, 10, 64)
		switch {
		case leftNumeric == nil && rightNumeric == nil:
			if leftNumber != rightNumber {
				if leftNumber < rightNumber {
					return -1
				}
				return 1
			}
		case leftNumeric == nil:
			// A numeric segment outranks a textual one, matching how a release
			// sorts above a prerelease suffix.
			return 1
		case rightNumeric == nil:
			return -1
		default:
			if leftField != rightField {
				if leftField < rightField {
					return -1
				}
				return 1
			}
		}
	}
	return 0
}

func splitVersion(version string) []string {
	return strings.FieldsFunc(version, func(character rune) bool {
		return character == '.' || character == '-' || character == '+' || character == '~' || character == '_'
	})
}
