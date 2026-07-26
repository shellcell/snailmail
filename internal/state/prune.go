package state

import (
	"errors"
	"fmt"
	"sort"
)

type VersionComparator func(left, right string) (int, error)

func PrunePlacements(lock *RepositoryLock, keep int, compare VersionComparator) (int, error) {
	if keep < 1 {
		return 0, errors.New("prune retention must keep at least one version")
	}
	if compare == nil {
		return 0, errors.New("version comparator is required")
	}
	type partitionKey struct{ packageName, track, distro string }
	type placementKey struct {
		partition partitionKey
		version   string
	}
	partitions := make(map[partitionKey][]string)
	for _, placement := range lock.Placement {
		partition := partitionKey{packageName: placement.Package, track: placement.Track, distro: placement.Distro}
		partitions[partition] = append(partitions[partition], placement.Version)
	}
	remove := make(map[placementKey]bool)
	partitionNames := make([]partitionKey, 0, len(partitions))
	for partition := range partitions {
		partitionNames = append(partitionNames, partition)
	}
	sort.Slice(partitionNames, func(left, right int) bool {
		if partitionNames[left].packageName != partitionNames[right].packageName {
			return partitionNames[left].packageName < partitionNames[right].packageName
		}
		if partitionNames[left].track != partitionNames[right].track {
			return partitionNames[left].track < partitionNames[right].track
		}
		return partitionNames[left].distro < partitionNames[right].distro
	})
	for _, partition := range partitionNames {
		versions := append([]string(nil), partitions[partition]...)
		for index := 1; index < len(versions); index++ {
			for cursor := index; cursor > 0; cursor-- {
				comparison, err := compare(versions[cursor], versions[cursor-1])
				if err != nil {
					return 0, fmt.Errorf("compare %s versions %q and %q in track %q distro %q: %w", partition.packageName, versions[cursor], versions[cursor-1], partition.track, partition.distro, err)
				}
				if comparison < 0 || (comparison == 0 && versions[cursor] >= versions[cursor-1]) {
					break
				}
				versions[cursor], versions[cursor-1] = versions[cursor-1], versions[cursor]
			}
		}
		if len(versions) <= keep {
			continue
		}
		cutoff := versions[keep-1]
		for _, version := range versions[keep:] {
			comparison, err := compare(version, cutoff)
			if err != nil {
				return 0, fmt.Errorf("compare %s versions %q and %q in track %q distro %q: %w", partition.packageName, version, cutoff, partition.track, partition.distro, err)
			}
			if comparison != 0 {
				remove[placementKey{partition: partition, version: version}] = true
			}
		}
	}
	if len(remove) == 0 {
		return 0, nil
	}
	kept := lock.Placement[:0]
	removed := 0
	for _, placement := range lock.Placement {
		identity := placementKey{partition: partitionKey{packageName: placement.Package, track: placement.Track, distro: placement.Distro}, version: placement.Version}
		if remove[identity] {
			removed++
			continue
		}
		kept = append(kept, placement)
	}
	lock.Placement = kept
	canonicalizeLock(lock)
	return removed, nil
}
