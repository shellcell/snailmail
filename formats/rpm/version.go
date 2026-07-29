package rpm

import (
	"fmt"
	"strconv"
	"strings"
)

// CompareVersions orders two epoch-version-release strings the way RPM does.
//
// Epoch wins outright, then version, then release. An absent epoch is zero, so
// "1.0-1" and "0:1.0-1" are the same version.
func CompareVersions(left, right string) (int, error) {
	leftEpoch, leftVersion, leftRelease, err := splitEVR(left)
	if err != nil {
		return 0, err
	}
	rightEpoch, rightVersion, rightRelease, err := splitEVR(right)
	if err != nil {
		return 0, err
	}
	if leftEpoch != rightEpoch {
		if leftEpoch < rightEpoch {
			return -1, nil
		}
		return 1, nil
	}
	if result := CompareSegments(leftVersion, rightVersion); result != 0 {
		return result, nil
	}
	return CompareSegments(leftRelease, rightRelease), nil
}

// splitEVR parses "[epoch:]version[-release]".
func splitEVR(value string) (int64, string, string, error) {
	if value == "" {
		return 0, "", "", fmt.Errorf("rpm version is empty")
	}
	epoch := int64(0)
	if colon := strings.IndexByte(value, ':'); colon >= 0 {
		parsed, err := strconv.ParseInt(value[:colon], 10, 32)
		if err != nil || parsed < 0 {
			return 0, "", "", fmt.Errorf("rpm version %q has an invalid epoch", value)
		}
		epoch = parsed
		value = value[colon+1:]
	}
	version, release := value, ""
	if dash := strings.IndexByte(value, '-'); dash >= 0 {
		version, release = value[:dash], value[dash+1:]
	}
	if version == "" {
		return 0, "", "", fmt.Errorf("rpm version %q has no version part", value)
	}
	return epoch, version, release, nil
}

// CompareSegments is rpmvercmp: the comparison RPM applies to a version or a
// release on its own.
//
// It walks both strings segment by segment, where a segment is a run of digits
// or a run of letters, and anything else is a separator that only ends a
// segment. Two rules are easy to get wrong and are why this is not a simple
// lexical compare: a numeric segment always outranks an alphabetic one, so
// "1.10" is above "1.a"; and a tilde sorts before everything including the end
// of the string, which is how "1.0~rc1" stays below "1.0".
func CompareSegments(left, right string) int {
	if left == right {
		return 0
	}
	one, two := left, right
	for len(one) > 0 || len(two) > 0 {
		one = trimSeparators(one)
		two = trimSeparators(two)

		// A tilde sorts before everything, so a prerelease is below the release
		// it precedes even though it is the longer string.
		if strings.HasPrefix(one, "~") || strings.HasPrefix(two, "~") {
			if !strings.HasPrefix(one, "~") {
				return 1
			}
			if !strings.HasPrefix(two, "~") {
				return -1
			}
			one, two = one[1:], two[1:]
			continue
		}
		// A caret is the mirror image: it sorts after the end of a string, so a
		// snapshot taken after a release outranks the release itself.
		if strings.HasPrefix(one, "^") || strings.HasPrefix(two, "^") {
			if one == "" {
				return -1
			}
			if two == "" {
				return 1
			}
			if !strings.HasPrefix(one, "^") {
				return 1
			}
			if !strings.HasPrefix(two, "^") {
				return -1
			}
			one, two = one[1:], two[1:]
			continue
		}
		if one == "" || two == "" {
			break
		}

		numeric := isDigit(one[0])
		var segmentOne, segmentTwo string
		if numeric {
			segmentOne, one = takeWhile(one, isDigit)
			segmentTwo, two = takeWhile(two, isDigit)
		} else {
			segmentOne, one = takeWhile(one, isAlpha)
			segmentTwo, two = takeWhile(two, isAlpha)
		}
		// The segments differ in kind: the left is numeric and the right is not,
		// or the reverse. A number always outranks letters.
		if segmentTwo == "" {
			if numeric {
				return 1
			}
			return -1
		}
		if numeric {
			// Leading zeros carry no value, and then more digits means a larger
			// number — which is why this cannot be an integer conversion: a
			// version segment can be longer than any integer type.
			segmentOne = strings.TrimLeft(segmentOne, "0")
			segmentTwo = strings.TrimLeft(segmentTwo, "0")
			if len(segmentOne) != len(segmentTwo) {
				if len(segmentOne) > len(segmentTwo) {
					return 1
				}
				return -1
			}
		}
		if result := strings.Compare(segmentOne, segmentTwo); result != 0 {
			return result
		}
	}
	// Every segment matched; whichever string has anything left wins, and if
	// neither does they differed only in separators and are equal.
	switch {
	case one == "" && two == "":
		return 0
	case one == "":
		return -1
	default:
		return 1
	}
}

func trimSeparators(value string) string {
	for len(value) > 0 && !isDigit(value[0]) && !isAlpha(value[0]) && value[0] != '~' && value[0] != '^' {
		value = value[1:]
	}
	return value
}

func takeWhile(value string, accept func(byte) bool) (string, string) {
	end := 0
	for end < len(value) && accept(value[end]) {
		end++
	}
	return value[:end], value[end:]
}

func isDigit(character byte) bool { return character >= '0' && character <= '9' }

func isAlpha(character byte) bool {
	return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z')
}
