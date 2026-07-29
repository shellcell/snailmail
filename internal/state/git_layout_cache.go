package state

import (
	"sync"
)

// The layout of a Git repository — where its directory is, whether its history
// is complete — is asked for repeatedly during one operation and answered by
// spawning git each time. Measured on a two-repository apply: 47 git processes,
// of which 10 were these, at roughly 10ms of fork and exec apiece.
//
// Only layout and configuration are cached, never state. A repository does not
// move, become shallow, or gain a partial-clone filter while snailmail holds
// its workspace lock. HEAD and the working tree very much do change, and the
// repeated reads of those are not waste: requireCleanGitContext reads HEAD
// before and after validating precisely so it can refuse a revision that moved
// underneath it. Caching those would delete the check rather than speed it up.
//
// The cache lives for the process. Every command is one operation, so that is
// the same lifetime as the workspace lock without having to thread a carrier
// through every call site that needs a path.
var gitLayout struct {
	sync.Mutex
	answers map[string]string
	errors  map[string]error
}

// cachedGitLayout returns a remembered answer, or asks and remembers.
func cachedGitLayout(root, question string, ask func() (string, error)) (string, error) {
	key := root + "\x00" + question
	gitLayout.Lock()
	if answer, asked := gitLayout.answers[key]; asked {
		err := gitLayout.errors[key]
		gitLayout.Unlock()
		return answer, err
	}
	gitLayout.Unlock()

	// Asked outside the lock: git is slow enough that holding it would serialize
	// the concurrent repository preparation an apply now does. Two callers
	// racing on the same question both ask, and both get the same answer.
	answer, err := ask()

	gitLayout.Lock()
	defer gitLayout.Unlock()
	if gitLayout.answers == nil {
		gitLayout.answers = map[string]string{}
		gitLayout.errors = map[string]error{}
	}
	gitLayout.answers[key] = answer
	gitLayout.errors[key] = err
	return answer, err
}

// forgetGitLayout drops what has been remembered. Tests create many
// repositories at the same paths, where a real workspace is one repository for
// the life of a command.
func forgetGitLayout() {
	gitLayout.Lock()
	defer gitLayout.Unlock()
	gitLayout.answers = nil
	gitLayout.errors = nil
}
