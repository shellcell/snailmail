package apk

import (
	"fmt"
	"strconv"
	"strings"
)

// Alpine version suffixes, in the order apk ranks them. Everything before the
// unsuffixed release sorts below it and everything after sorts above, which is
// why "1.0_rc1" precedes "1.0" while "1.0_p1" follows it.
var suffixRank = map[string]int{
	"alpha": -5,
	"beta":  -4,
	"pre":   -3,
	"rc":    -2,
	// the unsuffixed release is 0
	"cvs": 1,
	"svn": 2,
	"git": 3,
	"hg":  4,
	"p":   5,
}

// version is a parsed Alpine version: dotted numbers, an optional letter, any
// number of ranked suffixes, and the package revision.
type version struct {
	numbers  []string
	letter   string
	suffixes []suffix
	revision int64
	// hasRevision distinguishes "1.0" from "1.0-r0", which apk does not treat
	// as the same version: the explicit revision is the higher of the two.
	hasRevision bool
}

type suffix struct {
	rank   int
	number int64
}

// CompareVersions orders two Alpine versions.
func CompareVersions(left, right string) (int, error) {
	parsedLeft, err := parseVersion(left)
	if err != nil {
		return 0, err
	}
	parsedRight, err := parseVersion(right)
	if err != nil {
		return 0, err
	}
	return compare(parsedLeft, parsedRight), nil
}

func compare(left, right version) int {
	// Dotted numbers first. A part that is absent on one side is zero, so
	// "1.2" and "1.2.0" compare equal up to that point.
	for index := 0; index < len(left.numbers) || index < len(right.numbers); index++ {
		leftPart, rightPart := "0", "0"
		if index < len(left.numbers) {
			leftPart = left.numbers[index]
		}
		if index < len(right.numbers) {
			rightPart = right.numbers[index]
		}
		if result := compareNumber(leftPart, rightPart); result != 0 {
			return result
		}
	}
	if result := strings.Compare(left.letter, right.letter); result != 0 {
		return result
	}
	for index := 0; index < len(left.suffixes) || index < len(right.suffixes); index++ {
		// An absent suffix is the unsuffixed release, rank zero: that is what
		// puts "1.0" above "1.0_rc1" and below "1.0_p1".
		leftSuffix, rightSuffix := suffix{}, suffix{}
		if index < len(left.suffixes) {
			leftSuffix = left.suffixes[index]
		}
		if index < len(right.suffixes) {
			rightSuffix = right.suffixes[index]
		}
		if leftSuffix.rank != rightSuffix.rank {
			if leftSuffix.rank < rightSuffix.rank {
				return -1
			}
			return 1
		}
		if leftSuffix.number != rightSuffix.number {
			if leftSuffix.number < rightSuffix.number {
				return -1
			}
			return 1
		}
	}
	// An explicit revision outranks an absent one whatever its value, so
	// "1.0-r0" is above "1.0": apk sees one more token rather than a revision
	// of zero. Only once both carry one do the numbers decide.
	if left.hasRevision != right.hasRevision {
		if right.hasRevision {
			return -1
		}
		return 1
	}
	if left.revision != right.revision {
		if left.revision < right.revision {
			return -1
		}
		return 1
	}
	return 0
}

// compareNumber orders one dotted component. A leading zero makes it a
// fraction rather than an integer — "1.05" is below "1.1" — so those compare
// as text, which is what apk does.
func compareNumber(left, right string) int {
	if strings.HasPrefix(left, "0") || strings.HasPrefix(right, "0") {
		if len(left) > 1 || len(right) > 1 {
			return strings.Compare(strings.TrimRight(left, "0"), strings.TrimRight(right, "0"))
		}
	}
	leftValue, leftErr := strconv.ParseInt(left, 10, 64)
	rightValue, rightErr := strconv.ParseInt(right, 10, 64)
	if leftErr != nil || rightErr != nil {
		return strings.Compare(left, right)
	}
	switch {
	case leftValue < rightValue:
		return -1
	case leftValue > rightValue:
		return 1
	default:
		return 0
	}
}

// parseVersion reads "1.2.3a_rc1-r4".
func parseVersion(value string) (version, error) {
	if value == "" {
		return version{}, fmt.Errorf("apk version is empty")
	}
	parsed := version{}
	remainder := value

	// The revision is the last "-r<N>", and a dash means nothing else here.
	if index := strings.LastIndex(remainder, "-r"); index >= 0 {
		revision, err := strconv.ParseInt(remainder[index+2:], 10, 64)
		if err != nil || revision < 0 {
			return version{}, fmt.Errorf("apk version %q has an invalid revision", value)
		}
		parsed.revision = revision
		parsed.hasRevision = true
		remainder = remainder[:index]
	}
	if strings.Contains(remainder, "-") {
		return version{}, fmt.Errorf("apk version %q has a stray dash", value)
	}

	// Suffixes follow underscores and each may carry a number.
	if index := strings.IndexByte(remainder, '_'); index >= 0 {
		for _, part := range strings.Split(remainder[index+1:], "_") {
			name := strings.TrimRight(part, "0123456789")
			rank, known := suffixRank[name]
			if !known {
				return version{}, fmt.Errorf("apk version %q has unknown suffix %q", value, name)
			}
			number := int64(0)
			if digits := part[len(name):]; digits != "" {
				parsedNumber, err := strconv.ParseInt(digits, 10, 64)
				if err != nil {
					return version{}, fmt.Errorf("apk version %q has an invalid suffix number", value)
				}
				number = parsedNumber
			}
			parsed.suffixes = append(parsed.suffixes, suffix{rank: rank, number: number})
		}
		remainder = remainder[:index]
	}

	// A single trailing letter is a revision of the same upstream version.
	if remainder != "" {
		if last := remainder[len(remainder)-1]; last >= 'a' && last <= 'z' {
			parsed.letter = string(last)
			remainder = remainder[:len(remainder)-1]
		}
	}
	if remainder == "" {
		return version{}, fmt.Errorf("apk version %q has no numeric part", value)
	}
	for _, part := range strings.Split(remainder, ".") {
		if part == "" || strings.TrimLeft(part, "0123456789") != "" {
			return version{}, fmt.Errorf("apk version %q has a non-numeric component %q", value, part)
		}
		parsed.numbers = append(parsed.numbers, part)
	}
	return parsed, nil
}
