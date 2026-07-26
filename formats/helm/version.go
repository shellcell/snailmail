package helm

import "github.com/Masterminds/semver/v3"

func CompareVersions(left, right string) (int, error) {
	leftVersion, err := semver.NewVersion(left)
	if err != nil {
		return 0, err
	}
	rightVersion, err := semver.NewVersion(right)
	if err != nil {
		return 0, err
	}
	return leftVersion.Compare(rightVersion), nil
}
