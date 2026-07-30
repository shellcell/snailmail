// Package forgeio reads JSON from a forge, over either transport an adapter has.
//
// Where a vendor CLI exists — gh, glab — it is preferred, because it owns
// authentication and host resolution and snailmail never sees a token. Where one
// does not, or is not installed, the adapter speaks HTTP and presents a token
// from a broker.
//
// What is shared is not the endpoints but the hardening: a bounded read, a decode
// that accounts for the whole response, and every failure rendered as
// forge.ErrUnavailable so a gate refuses rather than guesses. That lives here
// because it is the part that must not differ by transport or provider — a second
// path to the same authorization must not be a weaker one.
package forgeio

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/shellcell/snailmail/forge"
)

// MaxResponseSize bounds a provider response. Review metadata is small, and an
// unbounded read would let a compromised or misconfigured endpoint exhaust
// memory during the one step that authorizes publication.
const MaxResponseSize = 4 << 20

// Request is one call to a provider CLI.
type Request struct {
	// Binary is the CLI to run, resolved on PATH so the operator's installation
	// and its stored credentials are the ones used.
	Binary string
	// Arguments are passed verbatim. Nothing here goes through a shell, so a
	// value carrying a space stays one argument.
	Arguments []string
	// WorkingDirectory is the local checkout the CLI may need to resolve which
	// host and account to use.
	WorkingDirectory string
	// Endpoint names what was asked, for error messages. It is not used to build
	// the call.
	Endpoint string
}

// ReadJSON runs the CLI and decodes its output into target.
//
// Every failure is forge.ErrUnavailable. A provider that cannot be reached, that
// answers with something other than JSON, or that answers with more than one
// document all mean the same thing to a gate: review state is unknown, and
// unknown must not authorize.
func ReadJSON(ctx context.Context, request Request, target any) error {
	command := exec.CommandContext(ctx, request.Binary, request.Arguments...)
	command.Dir = request.WorkingDirectory
	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("%w: %s %s", forge.ErrUnavailable, request.Binary, request.Endpoint)
	}
	if len(output) > MaxResponseSize {
		return fmt.Errorf("%w: response from %s exceeds the read limit", forge.ErrUnavailable, request.Endpoint)
	}
	// A second document would mean something other than the API answered, or
	// answered twice; taking the first would be reading review evidence from a
	// source that has not been identified. Shared with the HTTP transport so the
	// two cannot come to disagree about what a complete answer is.
	return decodeSingle(output, target, request.Endpoint)
}
