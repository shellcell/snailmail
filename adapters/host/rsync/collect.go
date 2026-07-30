package rsynchost

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/shellcell/snailmail/host"
	"github.com/shellcell/snailmail/internal/hexdigest"
)

// Collect removes release directories no longer needed.
//
// The same accumulation an object store has, for the same reason: a publication
// writes a whole tree under .snailmail/releases/<tree>/ and the swap that makes it
// live does not remove the one it replaced. A project publishing daily leaves a
// copy a day on the far side.
//
// Simpler than the object store's, because of what this host does not do. A
// release is a self-contained directory named by its tree digest, so there is
// nothing at a canonical path outside it to orphan. And Restore is not offered, so
// there is no rollback target that has to outlive the revision that superseded it —
// the only things that must survive are the live revision and whatever the
// retention names.
//
// The live revision is read from the far side rather than trusted from the caller,
// so a caller whose ledger is behind cannot delete what is being served.
func (adapter *Adapter) Collect(ctx context.Context, repository host.Repository,
	retention host.Retention) (host.CollectResult, error) {
	root, err := remoteRoot(repository)
	if err != nil {
		return host.CollectResult{}, err
	}
	keep := make(map[string]bool, len(retention.KeepTrees)+1)
	for _, tree := range retention.KeepTrees {
		if !hexdigest.ValidSHA256(tree) {
			return host.CollectResult{}, invalid("collect rsync releases",
				fmt.Errorf("retention names %q, which is not a tree digest", tree))
		}
		keep[tree] = true
	}
	observed, err := adapter.Observe(ctx, repository)
	if err != nil {
		return host.CollectResult{}, err
	}
	if observed.TreeSHA256 == "" {
		// Nothing managed is being served, so no release here can be identified as
		// superseded. Refused rather than continued: without knowing what is live,
		// every deletion is a guess.
		return host.CollectResult{}, invalid("collect rsync releases",
			errors.New("no revision is published, so no release can be identified as superseded"))
	}
	keep[observed.TreeSHA256] = true

	base := path.Dir(root)
	releases := path.Join(base, releasesDirectory)
	present, err := adapter.releaseTrees(ctx, releases)
	if err != nil {
		return host.CollectResult{}, err
	}
	result := host.CollectResult{DryRun: retention.DryRun}
	for _, tree := range present {
		if keep[tree] {
			result.KeptRevisions++
			continue
		}
		size, err := adapter.releaseBytes(ctx, path.Join(releases, tree))
		if err != nil {
			return host.CollectResult{}, err
		}
		result.Removed++
		result.RemovedBytes += size
		if retention.DryRun {
			continue
		}
		if _, err := adapter.runner.Run(ctx, []string{"rm", "-rf", path.Join(releases, tree)}); err != nil {
			return host.CollectResult{}, infrastructure("delete superseded rsync release", err)
		}
	}
	return result, nil
}

// releaseTrees lists the revisions present, ignoring anything that does not name
// one. A directory here that this adapter did not write is left alone: deleting
// what it does not recognise is not collection.
func (adapter *Adapter) releaseTrees(ctx context.Context, releases string) ([]string, error) {
	output, err := adapter.runner.Run(ctx, []string{"ls", releases})
	if err != nil {
		if _, exited := exitCode(err); exited {
			// Nothing has been published through a release directory yet.
			return nil, nil
		}
		return nil, infrastructure("list rsync releases", err)
	}
	var trees []string
	for _, line := range strings.Split(string(output), "\n") {
		name := strings.TrimSpace(line)
		if hexdigest.ValidSHA256(name) {
			trees = append(trees, name)
		}
	}
	return trees, nil
}

// releaseBytes reports what a release occupies, so an operator can see what a
// collection is worth before running it.
func (adapter *Adapter) releaseBytes(ctx context.Context, release string) (int64, error) {
	output, err := adapter.runner.Run(ctx, []string{"du", "-sk", release})
	if err != nil {
		// Size is for reporting, not for deciding. A release whose size cannot be
		// read is still collectable, and refusing the whole collection over a number
		// nobody acts on would be the wrong trade.
		return 0, nil
	}
	fields := strings.Fields(string(output))
	if len(fields) == 0 {
		return 0, nil
	}
	kilobytes, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0, nil
	}
	return kilobytes * 1024, nil
}
