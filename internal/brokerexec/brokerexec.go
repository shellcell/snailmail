// Package brokerexec runs an operator-supplied helper program that hands
// snailmail a secret.
//
// Two brokers use it: the one that issues read credentials for a private host,
// and the one that supplies a forge API token. What they ask for and what they
// get back differ; how the helper is run must not, because that is where the
// hardening lives.
//
// The helper is snapshotted into a private directory and executed from there, so
// the program that answers is the one that was resolved at startup rather than
// whatever occupies that path later. Its environment is reduced to a declared
// allow-list, its output is bounded, and the request reaches it on stdin rather
// than as an argument, where it would be visible in a process listing.
package brokerexec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// CommandTimeout bounds one helper run. A broker is asked for a secret in the
// middle of an operation that holds a lock, so a helper that never answers must
// not hold it forever.
const CommandTimeout = 30 * time.Second

// maxResponseSize bounds what a helper may print. A secret is small, and an
// unbounded read would let a misbehaving helper exhaust memory.
const maxResponseSize = 64 << 10

// Helper is a snapshotted helper program.
type Helper struct {
	mutex     sync.Mutex
	kind      string
	handle    *os.File
	directory string
	execPath  string
	identity  string
}

// Open resolves the helper named by an environment variable and snapshots it.
//
// kind names what this helper is for, and appears in every error, because an
// operator with both brokers configured needs to know which one refused.
func Open(kind, environment string) (*Helper, error) {
	named := os.Getenv(environment)
	if named == "" {
		return nil, fmt.Errorf("%s broker is not configured", kind)
	}
	resolved, err := exec.LookPath(named)
	if err != nil {
		return nil, fmt.Errorf("%s broker executable was not found", kind)
	}
	resolved, err = filepath.EvalSymlinks(resolved)
	if err != nil {
		return nil, fmt.Errorf("%s broker executable could not be resolved", kind)
	}
	source, err := os.Open(resolved)
	if err != nil {
		return nil, fmt.Errorf("%s broker executable could not be opened", kind)
	}
	var magic [4]byte
	if _, err := source.ReadAt(magic[:], 0); err != nil || !supportedExecutable(magic) {
		_ = source.Close()
		return nil, fmt.Errorf("%s broker must be a native executable", kind)
	}
	// The snapshot lives in a private directory so that retaining it by path,
	// which darwin requires, is still unreachable by other users.
	directory, err := os.MkdirTemp("", ".snailmail-broker-*")
	if err != nil {
		_ = source.Close()
		return nil, fmt.Errorf("%s broker executable could not be snapshotted", kind)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = source.Close()
		_ = os.RemoveAll(directory)
		return nil, fmt.Errorf("%s broker directory could not be protected", kind)
	}
	snapshot, err := os.CreateTemp(directory, "helper-*")
	if err != nil {
		_ = source.Close()
		_ = os.RemoveAll(directory)
		return nil, fmt.Errorf("%s broker executable could not be snapshotted", kind)
	}
	snapshotName := snapshot.Name()
	cleanup := func() {
		_ = snapshot.Close()
		_ = os.RemoveAll(directory)
	}
	hash := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(snapshot, hash), source)
	closeErr := source.Close()
	if copyErr != nil || closeErr != nil {
		cleanup()
		return nil, fmt.Errorf("%s broker executable could not be snapshotted", kind)
	}
	if err := snapshot.Chmod(0o500); err != nil {
		cleanup()
		return nil, fmt.Errorf("%s broker executable could not be protected", kind)
	}
	if err := snapshot.Sync(); err != nil {
		cleanup()
		return nil, fmt.Errorf("%s broker executable could not be prepared", kind)
	}
	if err := snapshot.Close(); err != nil {
		_ = os.RemoveAll(directory)
		return nil, fmt.Errorf("%s broker executable could not be prepared", kind)
	}
	handle, err := os.Open(snapshotName)
	if err != nil {
		_ = os.RemoveAll(directory)
		return nil, fmt.Errorf("%s broker executable could not be prepared", kind)
	}
	execPath, err := RetainSnapshot(snapshotName)
	if err != nil {
		_ = handle.Close()
		_ = os.RemoveAll(directory)
		return nil, fmt.Errorf("%s broker executable could not be protected", kind)
	}
	helper := &Helper{
		kind: kind, handle: handle, directory: directory, execPath: execPath,
		identity: hex.EncodeToString(hash.Sum(nil)),
	}
	runtime.SetFinalizer(helper, func(value *Helper) { _ = value.Close() })
	return helper, nil
}

// Named reports whether a helper is configured, so a caller can distinguish an
// absent broker from one that refused without running anything.
func Named(environment string) bool { return os.Getenv(environment) != "" }

// Identity is the digest of the snapshotted program, so a deployment receipt can
// record which helper answered.
func (helper *Helper) Identity() string { return helper.identity }

func (helper *Helper) Close() error {
	helper.mutex.Lock()
	defer helper.mutex.Unlock()
	runtime.SetFinalizer(helper, nil)
	if helper.handle == nil {
		return nil
	}
	err := helper.handle.Close()
	helper.handle = nil
	if helper.directory != "" {
		if removeErr := os.RemoveAll(helper.directory); err == nil {
			err = removeErr
		}
		helper.directory = ""
	}
	return err
}

// Run hands request to the helper on stdin and decodes its reply into target.
//
// The reply must be exactly one JSON document with no unknown fields: a helper
// that answered with something the caller does not understand has not answered
// the question that was asked, and guessing which part to believe is worse than
// refusing. The buffer holding it is cleared before returning, so a secret does
// not outlive the call in a heap the collector has not reused.
func (helper *Helper) Run(ctx context.Context, request any, target any) error {
	encoded, err := json.Marshal(request)
	if err != nil {
		return err
	}
	helper.mutex.Lock()
	defer helper.mutex.Unlock()
	if helper.handle == nil {
		return fmt.Errorf("%s broker is closed", helper.kind)
	}
	commandCtx, cancel := context.WithTimeout(ctx, CommandTimeout)
	defer cancel()
	command := exec.CommandContext(commandCtx, helper.execPath)
	command.ExtraFiles = []*os.File{helper.handle}
	command.Stdin = bytes.NewReader(encoded)
	command.Env = Environment()
	output := &limitedBuffer{maximum: maxResponseSize, kind: helper.kind}
	defer func() { clear(output.content) }()
	command.Stdout = output
	err = command.Run()
	runtime.KeepAlive(helper)
	if err != nil {
		return fmt.Errorf("%s broker command failed", helper.kind)
	}
	decoder := json.NewDecoder(bytes.NewReader(output.content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%s broker returned an invalid response", helper.kind)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s broker returned trailing data", helper.kind)
	}
	return nil
}

// Environment is the reduced environment a helper runs in. Everything a helper
// legitimately needs to find its own configuration and reach a cloud provider is
// listed; anything else — including the caller's own secrets — is not passed on.
func Environment() []string {
	allowed := map[string]bool{
		"HOME": true, "XDG_CONFIG_HOME": true, "SSL_CERT_FILE": true, "SSL_CERT_DIR": true,
		"AWS_PROFILE": true, "AWS_REGION": true, "AWS_DEFAULT_REGION": true, "AWS_ROLE_ARN": true,
		"AWS_ROLE_SESSION_NAME": true, "AWS_WEB_IDENTITY_TOKEN_FILE": true,
		"AWS_SHARED_CREDENTIALS_FILE": true, "AWS_CONFIG_FILE": true,
	}
	environment := make([]string, 0)
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if allowed[name] || strings.HasPrefix(name, "SNAILMAIL_BROKER_") {
			environment = append(environment, entry)
		}
	}
	return environment
}

func supportedExecutable(magic [4]byte) bool {
	value := string(magic[:])
	return value == "\x7fELF" || value == "\xfe\xed\xfa\xce" || value == "\xfe\xed\xfa\xcf" ||
		value == "\xce\xfa\xed\xfe" || value == "\xcf\xfa\xed\xfe" || value == "\xca\xfe\xba\xbe" || value == "\xbe\xba\xfe\xca"
}

type limitedBuffer struct {
	content []byte
	maximum int
	kind    string
}

func (buffer *limitedBuffer) Write(content []byte) (int, error) {
	if len(content) > buffer.maximum-len(buffer.content) {
		return 0, fmt.Errorf("%s broker response exceeds limit", buffer.kind)
	}
	buffer.content = append(buffer.content, content...)
	return len(content), nil
}
