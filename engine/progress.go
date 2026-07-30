package engine

// ApplyProgress reports what an apply is doing while it does it.
//
// A publication takes minutes: building each repository, fetching artifacts a
// runner does not have, running a real client in a container per format, then
// switching hosts live. Reporting nothing until it finishes means a caller cannot
// tell a slow apply from a hung one — and the reasonable response to a hung
// publication is to kill it, which is the worst thing to do to one holding a
// workspace lock partway through.
//
// A callback rather than a writer, so the engine does not decide how progress is
// presented. The command renders lines; a test can count events; a future TUI can
// draw them. Nil means report nothing, which is what every existing caller gets.
//
// Called from the goroutine that does the work, and possibly from several at once
// where a phase runs concurrently, so an implementation must be safe to call from
// more than one goroutine.
type ApplyProgress func(ApplyEvent)

// ApplyEvent is one step of an apply.
//
// Every field is known before the work starts — the plan already enumerates the
// repositories and their changes — so this reports a list rather than estimating
// progress it cannot know.
type ApplyEvent struct {
	// Phase is which part of the apply this is, in the order they happen:
	// prepare, authorize, stage, record, publish.
	Phase ApplyPhase
	// Repository is the repository being worked on, empty for a phase that is not
	// per-repository.
	Repository string
	// Index and Total place this repository in the run, counting from one. Zero
	// when the phase is not per-repository.
	Index, Total int
	// Detail says something specific about this step where there is something
	// worth saying — the format being verified, the number of artifacts fetched.
	Detail string
}

// ApplyPhase names a stage of an apply. The strings are part of the reported
// output, so they are stable.
type ApplyPhase string

const (
	// PhasePrepare covers building a repository, fetching whatever artifacts are
	// missing, and verifying the built tree with a real client. It is the slowest
	// phase by a wide margin.
	PhasePrepare ApplyPhase = "prepare"
	// PhaseAuthorize is the gate check: whether this change may take effect.
	PhaseAuthorize ApplyPhase = "authorize"
	// PhaseStage writes the built tree to the host without making it live.
	PhaseStage ApplyPhase = "stage"
	// PhaseRecord commits the publication ledger, before anything is switched, so
	// an interrupted publication is still accounted for.
	PhaseRecord ApplyPhase = "record"
	// PhasePublish switches the host to the new revision. This is the first point
	// at which a client sees anything change.
	PhasePublish ApplyPhase = "publish"
)

// report sends one event, doing nothing when no callback was given.
func (preparation *applyPreparation) report(event ApplyEvent) {
	if preparation.request.Progress == nil {
		return
	}
	preparation.request.Progress(event)
}
