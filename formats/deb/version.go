package deb

import (
	"errors"
	"strings"
)

func CompareVersions(left, right string) (int, error) {
	if !validVersion(left) || !validVersion(right) {
		return 0, errors.New("invalid Debian version")
	}
	leftEpoch, leftUpstream, leftRevision := splitVersion(left)
	rightEpoch, rightUpstream, rightRevision := splitVersion(right)
	if comparison := compareNumeric(leftEpoch, rightEpoch); comparison != 0 {
		return comparison, nil
	}
	if comparison := compareVersionPart(leftUpstream, rightUpstream); comparison != 0 {
		return comparison, nil
	}
	return compareVersionPart(leftRevision, rightRevision), nil
}

func splitVersion(version string) (epoch, upstream, revision string) {
	epoch = "0"
	if separator := strings.IndexByte(version, ':'); separator >= 0 {
		epoch, version = version[:separator], version[separator+1:]
		epoch = strings.TrimPrefix(epoch, "+")
	}
	revision = "0"
	if separator := strings.LastIndexByte(version, '-'); separator >= 0 {
		version, revision = version[:separator], version[separator+1:]
	}
	return epoch, version, revision
}

func compareVersionPart(left, right string) int {
	for len(left) != 0 || len(right) != 0 {
		for (len(left) != 0 && !isDigit(left[0])) || (len(right) != 0 && !isDigit(right[0])) {
			leftOrder, rightOrder := versionOrder(firstByte(left)), versionOrder(firstByte(right))
			if leftOrder < rightOrder {
				return -1
			}
			if leftOrder > rightOrder {
				return 1
			}
			if len(left) != 0 && !isDigit(left[0]) {
				left = left[1:]
			}
			if len(right) != 0 && !isDigit(right[0]) {
				right = right[1:]
			}
		}
		leftDigits, leftRest := takeDigits(left)
		rightDigits, rightRest := takeDigits(right)
		if comparison := compareNumeric(leftDigits, rightDigits); comparison != 0 {
			return comparison
		}
		left, right = leftRest, rightRest
	}
	return 0
}

func compareNumeric(left, right string) int {
	left = strings.TrimLeft(left, "0")
	right = strings.TrimLeft(right, "0")
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

func takeDigits(value string) (string, string) {
	index := 0
	for index < len(value) && isDigit(value[index]) {
		index++
	}
	return value[:index], value[index:]
}

func firstByte(value string) byte {
	if value == "" {
		return 0
	}
	return value[0]
}

func versionOrder(value byte) int {
	switch {
	case value == '~':
		return -1
	case value == 0 || isDigit(value):
		return 0
	case (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z'):
		return int(value)
	default:
		return int(value) + 256
	}
}

func isDigit(value byte) bool {
	return value >= '0' && value <= '9'
}
