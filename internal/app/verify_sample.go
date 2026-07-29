package app

import (
	"sort"

	"github.com/shellcell/snailmail/formats"
	"github.com/shellcell/snailmail/internal/domain"
)

// VersionScope says how much of a repository one client run exercises.
//
// It is a property of the run rather than of the repository: the manifest lists
// every version a client must be able to install whichever scope is used, so
// what the repository claims is unchanged by how much of it was sampled.
type VersionScope string

const (
	// SampledVersions installs the newest and oldest version of each package on
	// each architecture. The default, because the cost of the alternative grows
	// with every release ever kept.
	SampledVersions VersionScope = "sampled"
	// AllVersions installs every retained version.
	AllVersions VersionScope = "all"
)

// selection applies the scope, falling back to verifying everything for any
// value that is not recognised — an unreadable policy must not quietly check
// less than it was asked to.
func (scope VersionScope) selection(cases []domain.VerificationCase, compare func(left, right string) (int, error)) []domain.VerificationCase {
	if scope != SampledVersions {
		return cases
	}
	return SampleVerificationCases(cases, compare)
}

// The comparators each container verifier samples with. A version this format
// cannot order is one nothing can choose between, which SampleVerificationCases
// answers by verifying the whole group.
func formatCompare(name string) func(left, right string) (int, error) {
	selected, err := formats.For(name)
	if err != nil {
		return func(string, string) (int, error) { return 0, err }
	}
	return selected.CompareVersions
}

func debCompare(left, right string) (int, error) { return formatCompare("deb")(left, right) }
func rpmCompare(left, right string) (int, error) { return formatCompare("rpm")(left, right) }
func apkCompare(left, right string) (int, error) { return formatCompare("apk")(left, right) }

// SampleVerificationCases chooses which of a repository's package versions to
// install with a real client.
//
// Client verification costs one container per case, so verifying every retained
// version makes publication cost grow with history — a number that only goes
// up. What that spends is largely repetition: structural verification already
// checks every published file against its locked digest for every version, so
// what a client adds is that a real apt, dnf or apk agrees with the index, and
// that is mostly a property of the format rather than of each version in it.
//
// The newest version of each package on each architecture is what people
// actually install, and the oldest retained one is what would break first if a
// regenerated index stopped serving anything but the latest. Checking both
// keeps the property worth having — that a non-latest entry is installable —
// at a cost that does not grow.
//
// The manifest still lists every case. This selects what one run exercises, so
// what the repository claims must be installable is unchanged by how much of it
// was sampled.
func SampleVerificationCases(cases []domain.VerificationCase, compare func(left, right string) (int, error)) []domain.VerificationCase {
	if len(cases) < 2 {
		return cases
	}
	type coordinate struct{ name, architecture string }
	groups := make(map[coordinate][]domain.VerificationCase, len(cases))
	order := make([]coordinate, 0, len(cases))
	for _, verification := range cases {
		name := verification.Package
		if name == "" {
			name = verification.Project
		}
		key := coordinate{name: name, architecture: verification.Architecture}
		if _, seen := groups[key]; !seen {
			order = append(order, key)
		}
		groups[key] = append(groups[key], verification)
	}

	selected := make([]domain.VerificationCase, 0, len(order)*2)
	for _, key := range order {
		group := groups[key]
		if len(group) < 3 {
			// Two or fewer are already the newest and the oldest.
			selected = append(selected, group...)
			continue
		}
		failed := false
		sort.SliceStable(group, func(left, right int) bool {
			order, err := compare(group[left].Version, group[right].Version)
			if err != nil {
				failed = true
				return false
			}
			return order < 0
		})
		if failed {
			// A version this format cannot order is one nothing here can choose
			// between, so everything in the group is verified rather than an
			// arbitrary pair of it.
			selected = append(selected, groups[key]...)
			continue
		}
		selected = append(selected, group[0], group[len(group)-1])
	}
	// Back into the order the manifest lists them, so a failure names the same
	// case whether or not sampling was in play.
	position := make(map[domain.VerificationCase]int, len(cases))
	for index, verification := range cases {
		if _, seen := position[verification]; !seen {
			position[verification] = index
		}
	}
	sort.SliceStable(selected, func(left, right int) bool {
		return position[selected[left]] < position[selected[right]]
	})
	return selected
}
