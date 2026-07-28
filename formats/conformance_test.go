package formats

import (
	"strings"
	"testing"
	"time"

	"github.com/shellcell/snailmail/internal/knowledge"
)

// PLAN.md §5: "Tier is a promise, not a vibe." Every registered format runs the
// same assertions, so a new ecosystem inherits this suite by registering rather
// than by someone remembering to write these tests again.

func TestEveryFormatHasDistinctStableIdentity(t *testing.T) {
	names := make(map[string]bool)
	identities := make(map[string]bool)
	for _, format := range All() {
		name, identity := format.Name(), format.ID()
		if name == "" || identity == "" {
			t.Fatalf("format %q has an empty name or identity", name)
		}
		// The identity is recorded in generated repository manifests and must
		// carry a version, so output changes are detectable.
		if !strings.Contains(identity, "/v") {
			t.Errorf("format %q identity %q carries no version", name, identity)
		}
		if !strings.HasPrefix(identity, name+"/") {
			t.Errorf("format %q identity %q does not derive from its name", name, identity)
		}
		if names[name] || identities[identity] {
			t.Errorf("format %q or identity %q is registered twice", name, identity)
		}
		names[name], identities[identity] = true, true
	}
	if len(names) == 0 {
		t.Fatal("no formats are registered")
	}
}

func TestForResolvesEveryRegisteredName(t *testing.T) {
	for _, name := range Names() {
		format, err := For(name)
		if err != nil {
			t.Fatalf("registered name %q does not resolve: %v", name, err)
		}
		if format.Name() != name {
			t.Errorf("name %q resolved to format %q", name, format.Name())
		}
		if !Supported(name) {
			t.Errorf("registered name %q is not reported as supported", name)
		}
	}
	if _, err := For("not-a-format"); err == nil {
		t.Fatal("an unregistered name resolved")
	}
	if Supported("not-a-format") {
		t.Fatal("an unregistered name is reported as supported")
	}
}

func TestEveryFormatBoundsArtifactSize(t *testing.T) {
	for _, format := range All() {
		size := format.MaxArtifactSize()
		if size <= 0 {
			t.Errorf("format %q does not bound artifact size", format.Name())
		}
		// An unbounded-in-practice limit defeats the purpose; nothing legitimate
		// in these ecosystems approaches four gigabytes.
		if size > 4<<30 {
			t.Errorf("format %q artifact limit %d is too loose to bound memory", format.Name(), size)
		}
	}
}

func TestEveryFormatRejectsUnrelatedFilenames(t *testing.T) {
	for _, format := range All() {
		for _, name := range []string{"", "README.md", "index.html", "../escape", "no-extension"} {
			if format.IsArtifactFilename(name) {
				t.Errorf("format %q accepted %q as an artifact filename", format.Name(), name)
			}
		}
	}
}

func TestEveryFormatNormalizesNamesIdempotently(t *testing.T) {
	for _, format := range All() {
		for _, name := range []string{"Simple", "with-dash", "with_underscore", "with.dot", "UPPER"} {
			once := format.NormalizeName(name)
			if twice := format.NormalizeName(once); twice != once {
				t.Errorf("format %q normalization is not idempotent: %q then %q", format.Name(), once, twice)
			}
			if once == "" {
				t.Errorf("format %q normalized %q to an empty name", format.Name(), name)
			}
		}
	}
}

func TestEveryFormatOrdersVersionsConsistently(t *testing.T) {
	// Only the shape is asserted here, because precedence rules are
	// per-ecosystem and each format tests its own in detail.
	for _, format := range All() {
		equal, err := format.CompareVersions("1.0.0", "1.0.0")
		if err != nil {
			t.Fatalf("format %q cannot compare equal versions: %v", format.Name(), err)
		}
		if equal != 0 {
			t.Errorf("format %q reports 1.0.0 != 1.0.0 (%d)", format.Name(), equal)
		}
		ascending, err := format.CompareVersions("1.0.0", "2.0.0")
		if err != nil {
			t.Fatalf("format %q cannot compare ordered versions: %v", format.Name(), err)
		}
		descending, err := format.CompareVersions("2.0.0", "1.0.0")
		if err != nil {
			t.Fatal(err)
		}
		if ascending >= 0 || descending <= 0 {
			t.Errorf("format %q does not order 1.0.0 before 2.0.0 (%d, %d)", format.Name(), ascending, descending)
		}
		if ascending != -descending {
			t.Errorf("format %q comparison is not antisymmetric (%d, %d)", format.Name(), ascending, descending)
		}
	}
}

func TestEveryFormatGivesEveryArtifactACoordinate(t *testing.T) {
	artifact := Artifact{Filename: "thing-1.0.0.bin", Architecture: "amd64"}
	for _, format := range All() {
		coordinate := format.ArtifactCoordinate(artifact)
		if coordinate == "" {
			t.Errorf("format %q gives no coordinate to an artifact", format.Name())
		}
		if repeated := format.ArtifactCoordinate(artifact); repeated != coordinate {
			t.Errorf("format %q coordinate is unstable: %q then %q", format.Name(), coordinate, repeated)
		}
	}
}

// A format that carries distributions must render a distinct commit path per
// suite, otherwise two suites would publish over each other.
func TestDistroFormatsSeparateSuitesInCommitPaths(t *testing.T) {
	for _, format := range All() {
		stable := format.CommitPaths(Repository{Suite: "stable"})
		testing := format.CommitPaths(Repository{Suite: "testing"})
		if len(stable) == 0 {
			t.Errorf("format %q declares no commit paths", format.Name())
			continue
		}
		same := strings.Join(stable, ",") == strings.Join(testing, ",")
		if format.SupportsDistros() == same {
			t.Errorf("format %q supports distros = %v but its commit paths %v suites",
				format.Name(), format.SupportsDistros(), map[bool]string{true: "ignore", false: "separate"}[same])
		}
	}
}

// An implementation may lag the ecosystem — Helm defines .prov signing that
// this tool does not yet produce — but it must never claim to sign a format the
// ecosystem cannot sign, because that would let a repository be configured for
// a signature no client would ever check. Implementing signing therefore
// implies the knowledge bundle permits it, and not the reverse.
func TestImplementedSigningIsPermittedByKnowledgeBundle(t *testing.T) {
	permitted := make(map[string]bool)
	known := make(map[string]bool)
	for _, requirement := range knowledge.SigningRequirements() {
		known[requirement.Format] = true
		permitted[requirement.Format] = requirement.RepositorySigning
	}
	for _, format := range All() {
		if !known[format.Name()] {
			t.Errorf("format %q is registered but absent from the signing compatibility table", format.Name())
			continue
		}
		if format.ImplementsSigning() && !permitted[format.Name()] {
			t.Errorf("format %q implements repository signing that its ecosystem does not define", format.Name())
		}
	}
}

// An empty repository is still a valid repository, and its rendering must be a
// pure function of its declared inputs.
func TestEveryFormatBuildsAnEmptyRepositoryDeterministically(t *testing.T) {
	options := BuildOptions{
		Repository:  Repository{Suite: "stable", Component: "main", Architectures: []string{"amd64"}},
		GeneratedAt: time.Unix(0, 0).UTC(),
	}
	for _, format := range All() {
		first, err := format.Build(nil, options)
		if err != nil {
			t.Fatalf("format %q cannot build an empty repository: %v", format.Name(), err)
		}
		if first.Format != format.ID() {
			t.Errorf("format %q built an artifact identified as %q", format.Name(), first.Format)
		}
		if len(first.Files) == 0 {
			t.Errorf("format %q built an empty repository with no files at all", format.Name())
		}
		second, err := format.Build(nil, options)
		if err != nil {
			t.Fatal(err)
		}
		if len(first.Files) != len(second.Files) {
			t.Fatalf("format %q built different file counts from the same inputs", format.Name())
		}
		for index := range first.Files {
			if first.Files[index].Path != second.Files[index].Path ||
				string(first.Files[index].Content) != string(second.Files[index].Content) {
				t.Errorf("format %q build is not deterministic at %q", format.Name(), first.Files[index].Path)
			}
		}
	}
}

// Every commit path must be one the build actually produces, otherwise a host
// would be asked to switch a file that does not exist.
func TestCommitPathsExistInTheBuiltTree(t *testing.T) {
	repository := Repository{Suite: "stable", Component: "main", Architectures: []string{"amd64"}}
	for _, format := range All() {
		artifact, err := format.Build(nil, BuildOptions{Repository: repository, GeneratedAt: time.Unix(0, 0).UTC()})
		if err != nil {
			t.Fatal(err)
		}
		built := make(map[string]bool, len(artifact.Files))
		for _, file := range artifact.Files {
			built[file.Path] = true
		}
		for _, commitPath := range format.CommitPaths(repository) {
			if !built[commitPath] {
				t.Errorf("format %q names commit path %q that its build does not produce", format.Name(), commitPath)
			}
		}
	}
}
