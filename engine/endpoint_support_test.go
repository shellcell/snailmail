package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/shellcell/snailmail/host"
	"github.com/shellcell/snailmail/internal/state"
)

// host.Supports declares which formats a remote host can client-verify, and
// verifyEndpointClient is what actually does it. Nothing held the two together,
// so a format could be declared verifiable and route to a default that refuses —
// which rpm and apk on Pages did, turning a working repository into a failing
// one the moment a preview site was configured.
//
// A format without a served-endpoint probe now falls back to verifying the
// staged tree, so no declared pair reaches that refusal. The call below cannot
// succeed — there is no staged tree and no endpoint — but it distinguishes "this
// format has no implementation at all" from any other failure.
func TestNoDeclaredFormatIsRefusedOutright(t *testing.T) {
	for _, hostType := range host.KnownHostTypes() {
		if hostType == "local" {
			continue
		}
		for _, format := range host.SupportedFormats(hostType) {
			if !host.Supports(hostType, format).RemoteClientVerification {
				continue
			}
			err := verifyEndpointClient(context.Background(),
				state.Repository{Format: format, Host: state.HostConfig{Type: hostType}},
				t.TempDir(), host.ClientAccess{Endpoint: "https://example.test/repo"},
				ApplyWorkspaceRequest{StructuralOnly: true})
			if err != nil && strings.Contains(err.Error(), "client verification is not implemented") {
				t.Errorf("host %q declares %q verifiable, but the engine has no probe: %v", hostType, format, err)
			}
		}
	}
}
