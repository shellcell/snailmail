package commandcredential

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shellcell/snailmail/host"
)

const HelperEnvironment = "SNAILMAIL_CREDENTIAL_BROKER"

const brokerCommandTimeout = 30 * time.Second

type Broker struct {
	mutex     sync.Mutex
	helper    *os.File
	directory string
	execPath  string
	identity  string
}

func NewFromEnvironment() (*Broker, error) {
	helper := os.Getenv(HelperEnvironment)
	if helper == "" {
		return nil, errors.New("private read credential broker is not configured")
	}
	resolved, err := exec.LookPath(helper)
	if err != nil {
		return nil, errors.New("private read credential broker executable was not found")
	}
	resolved, err = filepath.EvalSymlinks(resolved)
	if err != nil {
		return nil, errors.New("private read credential broker executable could not be resolved")
	}
	source, err := os.Open(resolved)
	if err != nil {
		return nil, errors.New("private read credential broker executable could not be opened")
	}
	var magic [4]byte
	if _, err := source.ReadAt(magic[:], 0); err != nil || !supportedExecutable(magic) {
		_ = source.Close()
		return nil, errors.New("private read credential broker must be a native executable")
	}
	// The snapshot lives in a private directory so that retaining it by path,
	// which darwin requires, is still unreachable by other users.
	directory, err := os.MkdirTemp("", ".snailmail-credential-broker-*")
	if err != nil {
		_ = source.Close()
		return nil, errors.New("private read credential broker executable could not be snapshotted")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = source.Close()
		_ = os.RemoveAll(directory)
		return nil, errors.New("private read credential broker directory could not be protected")
	}
	snapshot, err := os.CreateTemp(directory, "helper-*")
	if err != nil {
		_ = source.Close()
		_ = os.RemoveAll(directory)
		return nil, errors.New("private read credential broker executable could not be snapshotted")
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
		return nil, errors.New("private read credential broker executable could not be snapshotted")
	}
	if err := snapshot.Chmod(0o500); err != nil {
		cleanup()
		return nil, errors.New("private read credential broker executable could not be protected")
	}
	if err := snapshot.Sync(); err != nil {
		cleanup()
		return nil, errors.New("private read credential broker executable could not be prepared")
	}
	if err := snapshot.Close(); err != nil {
		_ = os.RemoveAll(directory)
		return nil, errors.New("private read credential broker executable could not be prepared")
	}
	executable, err := os.Open(snapshotName)
	if err != nil {
		_ = os.RemoveAll(directory)
		return nil, errors.New("private read credential broker executable could not be prepared")
	}
	execPath, err := retainSnapshot(snapshotName)
	if err != nil {
		_ = executable.Close()
		_ = os.RemoveAll(directory)
		return nil, errors.New("private read credential broker executable could not be protected")
	}
	broker := &Broker{helper: executable, directory: directory, execPath: execPath, identity: hex.EncodeToString(hash.Sum(nil))}
	runtime.SetFinalizer(broker, func(value *Broker) { _ = value.Close() })
	return broker, nil
}

func (broker *Broker) Identity() string {
	return broker.identity
}

func (broker *Broker) Close() error {
	broker.mutex.Lock()
	defer broker.mutex.Unlock()
	runtime.SetFinalizer(broker, nil)
	if broker.helper == nil {
		return nil
	}
	err := broker.helper.Close()
	broker.helper = nil
	if broker.directory != "" {
		if removeErr := os.RemoveAll(broker.directory); err == nil {
			err = removeErr
		}
		broker.directory = ""
	}
	return err
}

func (broker *Broker) Issue(ctx context.Context, scope host.ReadScope) (host.BasicCredential, error) {
	if !validSHA256(scope.WorkspaceID) || scope.Repository == "" || !validSHA256(scope.HostIdentity) || scope.Bucket == "" || scope.Endpoint == "" ||
		!validSHA256(scope.PlanID) || scope.ChangeID == "" || !validSHA256(scope.TreeSHA256) || len(scope.Prefixes) == 0 {
		return nil, errors.New("credential scope is incomplete")
	}
	for _, prefix := range scope.Prefixes {
		if prefix == "" || strings.ContainsAny(prefix, "\x00\r\n") {
			return nil, errors.New("credential scope is invalid")
		}
	}
	broker.mutex.Lock()
	defer broker.mutex.Unlock()
	if broker.helper == nil {
		return nil, errors.New("credential broker is closed")
	}
	request, err := json.Marshal(scope)
	if err != nil {
		return nil, err
	}
	commandCtx, cancel := context.WithTimeout(ctx, brokerCommandTimeout)
	defer cancel()
	command := exec.CommandContext(commandCtx, broker.execPath)
	command.ExtraFiles = []*os.File{broker.helper}
	command.Stdin = bytes.NewReader(request)
	command.Env = brokerEnvironment()
	output := &limitedBuffer{maximum: 64 << 10}
	defer func() { clear(output.content) }()
	command.Stdout = output
	err = command.Run()
	runtime.KeepAlive(broker)
	if err != nil {
		return nil, errors.New("credential broker command failed")
	}
	decoder := json.NewDecoder(bytes.NewReader(output.content))
	decoder.DisallowUnknownFields()
	var response struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := decoder.Decode(&response); err != nil {
		return nil, errors.New("credential broker returned an invalid response")
	}
	if err := requireEOF(decoder); err != nil {
		return nil, err
	}
	expiresAt, err := time.Parse(time.RFC3339, response.ExpiresAt)
	if err != nil || !expiresAt.After(time.Now().UTC()) || expiresAt.After(time.Now().UTC().Add(15*time.Minute)) || response.Username == "" || response.Password == "" {
		return nil, errors.New("credential broker returned invalid or excessive credentials")
	}
	return &credential{username: response.Username, password: response.Password, expiresAt: expiresAt}, nil
}

func brokerEnvironment() []string {
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

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func supportedExecutable(magic [4]byte) bool {
	value := string(magic[:])
	return value == "\x7fELF" || value == "\xfe\xed\xfa\xce" || value == "\xfe\xed\xfa\xcf" ||
		value == "\xce\xfa\xed\xfe" || value == "\xcf\xfa\xed\xfe" || value == "\xca\xfe\xba\xbe" || value == "\xbe\xba\xfe\xca"
}

type limitedBuffer struct {
	content []byte
	maximum int
}

func (buffer *limitedBuffer) Write(content []byte) (int, error) {
	if len(content) > buffer.maximum-len(buffer.content) {
		return 0, errors.New("credential broker response exceeds limit")
	}
	buffer.content = append(buffer.content, content...)
	return len(content), nil
}

type credential struct {
	mutex     sync.Mutex
	username  string
	password  string
	expiresAt time.Time
}

func (credential *credential) Basic(_ context.Context) (string, string, error) {
	credential.mutex.Lock()
	defer credential.mutex.Unlock()
	if credential.username == "" || credential.password == "" || !time.Now().UTC().Before(credential.expiresAt) {
		return "", "", errors.New("private read credential is unavailable or expired")
	}
	return credential.username, credential.password, nil
}

func (credential *credential) Destroy() {
	credential.mutex.Lock()
	defer credential.mutex.Unlock()
	credential.username = ""
	credential.password = ""
	credential.expiresAt = time.Time{}
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("credential broker returned trailing data")
	}
	return nil
}
