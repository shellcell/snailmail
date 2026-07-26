package pypi

import (
	"errors"
	"regexp"
	"strings"
)

var pep440Pattern = regexp.MustCompile(`(?i)^v?(?:([0-9]+)!)?([0-9]+(?:\.[0-9]+)*)(?:[._-]?(alpha|beta|preview|pre|a|b|c|rc)[._-]?([0-9]*))?(?:(?:-([0-9]+))|(?:[._-]?(post|rev|r)[._-]?([0-9]*)))?(?:[._-]?(dev)[._-]?([0-9]*))?(?:\+([a-z0-9]+(?:[._-][a-z0-9]+)*))?$`)

type pep440Version struct {
	epoch, preNumber, postNumber, devNumber string
	release                                 []string
	prePhase                                int
	hasPre, hasPost, hasDev                 bool
	local                                   []string
}

func CompareVersions(left, right string) (int, error) {
	leftVersion, err := parsePEP440(left)
	if err != nil {
		return 0, err
	}
	rightVersion, err := parsePEP440(right)
	if err != nil {
		return 0, err
	}
	if comparison := compareNumericString(leftVersion.epoch, rightVersion.epoch); comparison != 0 {
		return comparison, nil
	}
	if comparison := compareRelease(leftVersion.release, rightVersion.release); comparison != 0 {
		return comparison, nil
	}
	if comparison := comparePre(leftVersion, rightVersion); comparison != 0 {
		return comparison, nil
	}
	if comparison := compareOptionalNumber(leftVersion.hasPost, leftVersion.postNumber, rightVersion.hasPost, rightVersion.postNumber, -1, 1); comparison != 0 {
		return comparison, nil
	}
	if comparison := compareOptionalNumber(leftVersion.hasDev, leftVersion.devNumber, rightVersion.hasDev, rightVersion.devNumber, 1, -1); comparison != 0 {
		return comparison, nil
	}
	return compareLocal(leftVersion.local, rightVersion.local), nil
}

func parsePEP440(value string) (pep440Version, error) {
	matches := pep440Pattern.FindStringSubmatch(strings.TrimSpace(value))
	if matches == nil {
		return pep440Version{}, errors.New("invalid PEP 440 version")
	}
	result := pep440Version{epoch: defaultNumber(matches[1]), release: strings.Split(matches[2], ".")}
	if matches[3] != "" {
		result.hasPre = true
		result.preNumber = defaultNumber(matches[4])
		switch strings.ToLower(matches[3]) {
		case "a", "alpha":
			result.prePhase = 0
		case "b", "beta":
			result.prePhase = 1
		default:
			result.prePhase = 2
		}
	}
	if matches[5] != "" || matches[6] != "" {
		result.hasPost = true
		result.postNumber = defaultNumber(matches[5])
		if matches[5] == "" {
			result.postNumber = defaultNumber(matches[7])
		}
	}
	if matches[8] != "" {
		result.hasDev = true
		result.devNumber = defaultNumber(matches[9])
	}
	if matches[10] != "" {
		result.local = strings.FieldsFunc(strings.ToLower(matches[10]), func(character rune) bool {
			return character == '.' || character == '-' || character == '_'
		})
	}
	return result, nil
}

func compareRelease(left, right []string) int {
	length := len(left)
	if len(right) > length {
		length = len(right)
	}
	for index := 0; index < length; index++ {
		leftPart, rightPart := "0", "0"
		if index < len(left) {
			leftPart = left[index]
		}
		if index < len(right) {
			rightPart = right[index]
		}
		if comparison := compareNumericString(leftPart, rightPart); comparison != 0 {
			return comparison
		}
	}
	return 0
}

func comparePre(left, right pep440Version) int {
	leftRank, rightRank := preRank(left), preRank(right)
	if leftRank < rightRank {
		return -1
	}
	if leftRank > rightRank {
		return 1
	}
	if leftRank != 0 {
		return 0
	}
	if left.prePhase < right.prePhase {
		return -1
	}
	if left.prePhase > right.prePhase {
		return 1
	}
	return compareNumericString(left.preNumber, right.preNumber)
}

func preRank(version pep440Version) int {
	if version.hasPre {
		return 0
	}
	if version.hasDev && !version.hasPost {
		return -1
	}
	return 1
}

func compareOptionalNumber(leftPresent bool, left string, rightPresent bool, right string, absentRank, presentRank int) int {
	leftRank, rightRank := absentRank, absentRank
	if leftPresent {
		leftRank = presentRank
	}
	if rightPresent {
		rightRank = presentRank
	}
	if leftRank < rightRank {
		return -1
	}
	if leftRank > rightRank {
		return 1
	}
	if !leftPresent {
		return 0
	}
	return compareNumericString(left, right)
}

func compareLocal(left, right []string) int {
	if len(left) == 0 && len(right) == 0 {
		return 0
	}
	if len(left) == 0 {
		return -1
	}
	if len(right) == 0 {
		return 1
	}
	length := len(left)
	if len(right) < length {
		length = len(right)
	}
	for index := 0; index < length; index++ {
		leftNumeric, rightNumeric := numericSegment(left[index]), numericSegment(right[index])
		switch {
		case leftNumeric && !rightNumeric:
			return 1
		case !leftNumeric && rightNumeric:
			return -1
		case leftNumeric:
			if comparison := compareNumericString(left[index], right[index]); comparison != 0 {
				return comparison
			}
		default:
			if left[index] < right[index] {
				return -1
			}
			if left[index] > right[index] {
				return 1
			}
		}
	}
	if len(left) < len(right) {
		return -1
	}
	if len(left) > len(right) {
		return 1
	}
	return 0
}

func compareNumericString(left, right string) int {
	left, right = strings.TrimLeft(left, "0"), strings.TrimLeft(right, "0")
	if len(left) < len(right) {
		return -1
	}
	if len(left) > len(right) {
		return 1
	}
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func defaultNumber(value string) string {
	if value == "" {
		return "0"
	}
	return value
}

func numericSegment(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}
