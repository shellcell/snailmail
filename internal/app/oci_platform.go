package app

// NeedsEmulation reports whether verifying this architecture requires an
// emulator on a linux/amd64 runner.
//
// It answers from the same per-format maps the verifiers select images with, so
// the workflow a workspace generates asks for emulation exactly when a
// verification would need it. An architecture the format does not recognise is
// treated as needing it: guessing that something unknown runs natively would
// produce a workflow that fails at the container rather than at the setup.
func NeedsEmulation(format, architecture string) bool {
	var platform string
	var err error
	switch format {
	case "deb":
		platform, err = debOCIPlatform(architecture)
	case "rpm":
		platform, err = rpmOCIPlatform(architecture)
	case "apk":
		platform, err = apkOCIPlatform(architecture)
	default:
		// A format with no per-architecture client has nothing to emulate.
		return false
	}
	if err != nil {
		return true
	}
	// An empty platform means the artifact runs anywhere, which is what noarch
	// packages say about themselves.
	return platform != "" && platform != nativeRunnerPlatform
}

// nativeRunnerPlatform is what a hosted runner executes without emulation.
const nativeRunnerPlatform = "linux/amd64"
