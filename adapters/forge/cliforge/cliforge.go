// Package cliforge reads JSON from a provider's own CLI.
//
// Both forge adapters delegate authentication and host resolution to the
// vendor's tool — gh, glab — rather than handling tokens themselves. What is
// shared is not the endpoints but the hardening around the call: a bounded read,
// a decode that accounts for the whole response, and every failure rendered as
// forge.ErrUnavailable so a gate refuses rather than guesses.
//
// That hardening lives here because it is the part that must not differ between
// providers. A second adapter that bounded its response differently, or accepted
// a body with trailing data, would be a weaker path to the same authorization.
package cliforge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	decoder := json.NewDecoder(bytes.NewReader(output))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: invalid response from %s", forge.ErrUnavailable, request.Endpoint)
	}
	// A second document means something other than the API answered, or answered
	// twice. Taking the first would be reading review evidence from a source that
	// has not been identified.
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing data in response from %s", forge.ErrUnavailable, request.Endpoint)
	}
	return nil
}
