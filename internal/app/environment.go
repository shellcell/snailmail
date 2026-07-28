package app

import (
	"os"
	"sort"
	"strings"
)

// runnerEnvironmentAllowlist is what a container runner legitimately needs to
// find its socket, configuration and credentials. Everything else — the signing
// passphrase and cloud credentials in particular — has no business reaching a
// process whose only job is to run a verification image.
var runnerEnvironmentAllowlist = map[string]bool{
	"PATH": true, "HOME": true, "TMPDIR": true, "USER": true, "LOGNAME": true,
	"LANG": true, "LC_ALL": true, "TERM": true,
	"XDG_RUNTIME_DIR": true, "XDG_CONFIG_HOME": true, "XDG_DATA_HOME": true,
	"SSL_CERT_FILE": true, "SSL_CERT_DIR": true,
	"DOCKER_HOST": true, "DOCKER_CONFIG": true, "DOCKER_CERT_PATH": true, "DOCKER_TLS_VERIFY": true,
	"CONTAINER_HOST": true, "CONTAINER_CONNECTION": true, "CONTAINERS_CONF": true,
	"CONTAINERS_STORAGE_CONF": true, "CONTAINERS_REGISTRIES_CONF": true,
	"REGISTRY_AUTH_FILE": true, "BUILDAH_ISOLATION": true,
	"HTTP_PROXY": true, "HTTPS_PROXY": true, "NO_PROXY": true,
	"http_proxy": true, "https_proxy": true, "no_proxy": true,
}

// runnerEnvironment returns the allowlisted subset of the process environment,
// in sorted order so a child environment is a deterministic function of its
// inputs.
func runnerEnvironment() []string {
	environment := make([]string, 0, len(runnerEnvironmentAllowlist))
	for _, entry := range os.Environ() {
		name, _, found := strings.Cut(entry, "=")
		if found && runnerEnvironmentAllowlist[name] {
			environment = append(environment, entry)
		}
	}
	sort.Strings(environment)
	return environment
}
