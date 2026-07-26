package engine

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shellcell/snailmail/internal/testutil"
	"github.com/shellcell/snailmail/source"
)

func TestDoctorInspectsPyPIDebianAndHelmReferences(t *testing.T) {
	directory := t.TempDir()
	wheelName, err := testutil.WriteWheel(directory, "demo", "1.2.3", ">=3.8")
	if err != nil {
		t.Fatal(err)
	}
	wheel := readDoctorFixture(t, wheelName)
	chartName, err := testutil.WriteHelmChart(directory, "demo", "1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	chart := readDoctorFixture(t, chartName)
	debName, err := testutil.WriteDeb(directory, "demo", "1.2.3-1", "amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	debPackage := readDoctorFixture(t, debName)
	packages := []byte(fmt.Sprintf("Package: demo\nVersion: 1.2.3-1\nArchitecture: amd64\nFilename: pool/demo.deb\nSize: %d\nSHA256: %s\n\n", len(debPackage), digest(debPackage)))
	fetcher := doctorMemoryFetcher{responses: map[string]source.Response{
		"https://repo.example/simple/demo/":                            {StatusCode: 200, ContentType: "text/html", Body: []byte(fmt.Sprintf(`<html><body><a href="../../files/%s#sha256=%s">%s</a></body></html>`, filepath.Base(wheelName), digest(wheel), filepath.Base(wheelName)))},
		"https://repo.example/files/" + filepath.Base(wheelName):       {StatusCode: 200, Body: wheel},
		"https://repo.example/index.yaml":                              {StatusCode: 200, Body: []byte(fmt.Sprintf("apiVersion: v1\nentries:\n  demo:\n    - name: demo\n      version: 1.2.3\n      digest: %s\n      urls:\n        - charts/%s\n", digest(chart), filepath.Base(chartName)))},
		"https://repo.example/charts/" + filepath.Base(chartName):      {StatusCode: 200, Body: chart},
		"https://repo.example/dists/stable/main/binary-amd64/Packages": {StatusCode: 200, Body: packages},
		"https://repo.example/pool/demo.deb":                           {StatusCode: 200, Body: debPackage},
	}}
	requests := []DoctorRequest{
		{URL: "https://repo.example", Project: "demo", Fetcher: fetcher},
		{URL: "https://repo.example", Format: "helm", Fetcher: fetcher},
		{URL: "https://repo.example/dists/stable/main/binary-amd64/Packages", Format: "deb", Fetcher: fetcher},
	}
	for _, request := range requests {
		result, err := Doctor(context.Background(), request)
		if err != nil {
			t.Fatalf("doctor %s: %v", request.Format, err)
		}
		if result.Entries != 1 || result.ArtifactsChecked != 1 || hasDoctorErrors(result.Findings) {
			t.Fatalf("doctor %s result %#v", request.Format, result)
		}
		if request.Project != "" && result.Format != "pypi" {
			t.Fatalf("project selector did not select PyPI: %#v", result)
		}
		if request.Format == "deb" {
			if _, ok := doctorFindingByCode(result.Findings, "signature.unverified"); !ok {
				t.Fatalf("direct Packages omitted trust warning: %#v", result.Findings)
			}
		}
	}
}

func TestDoctorAutoSelectsCompressedDebianIndex(t *testing.T) {
	packages := []byte("Package: demo\nVersion: 1.2.3-1\nArchitecture: amd64\nFilename: pool/demo.deb\nSize: 7\nSHA256: " + strings.Repeat("a", 64) + "\n\n")
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(packages); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	release := []byte(fmt.Sprintf("Suite: stable\nCodename: stable\nComponents: main\nArchitectures: all amd64\nValid-Until: Mon, 27 Jul 2026 12:00:00 GMT\nSHA256:\n %s %d main/binary-amd64/Packages.gz\n", digest(compressed.Bytes()), compressed.Len()))
	fetcher := doctorMemoryFetcher{responses: map[string]source.Response{
		"https://repo.example/dists/stable/Release":                       {StatusCode: 200, Body: release},
		"https://repo.example/dists/stable/main/binary-amd64/Packages.gz": {StatusCode: 200, Body: compressed.Bytes()},
		"https://repo.example/pool/demo.deb":                              {StatusCode: 404},
	}}
	result, err := Doctor(context.Background(), DoctorRequest{
		URL: "https://repo.example", Suite: "stable", Fetcher: fetcher,
		Now: time.Date(2026, time.July, 26, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Format != "deb" || result.Entries != 1 {
		t.Fatalf("compressed Debian result %#v", result)
	}
	if _, ok := doctorFindingByCode(result.Findings, "signature.unverified"); !ok {
		t.Fatalf("Debian Release omitted signature warning: %#v", result.Findings)
	}
}

func TestDoctorAutoProbesConventionalIndex(t *testing.T) {
	fetcher := doctorMemoryFetcher{responses: map[string]source.Response{
		"https://repo.example":         {StatusCode: 200, ContentType: "text/plain", Body: []byte("package service")},
		"https://repo.example/simple/": {StatusCode: 200, ContentType: "text/html", Body: []byte(`<html><body><a href="demo/">demo</a></body></html>`)},
	}}
	result, err := Doctor(context.Background(), DoctorRequest{URL: "https://repo.example", Fetcher: fetcher})
	if err != nil {
		t.Fatal(err)
	}
	if result.Format != "pypi" || result.IndexURL != "https://repo.example/simple/" || result.Entries != 1 {
		t.Fatalf("auto-probed result %#v", result)
	}
}

func TestDoctorAutoProbesAfterMissingBaseAndMalformedCandidate(t *testing.T) {
	fetcher := doctorMemoryFetcher{responses: map[string]source.Response{
		"https://repo.example":            {StatusCode: 404},
		"https://repo.example/simple/":    {StatusCode: 200, ContentType: "application/json", Body: []byte(`{"broken":`)},
		"https://repo.example/index.yaml": {StatusCode: 200, Body: []byte("apiVersion: v1\nentries: {}\n")},
	}}
	result, err := Doctor(context.Background(), DoctorRequest{URL: "https://repo.example", Fetcher: fetcher})
	if err != nil {
		t.Fatal(err)
	}
	if result.Format != "helm" || result.IndexURL != "https://repo.example/index.yaml" {
		t.Fatalf("auto-probed fallback result %#v", result)
	}
}

func TestDoctorRecognizesConcreteCompressedAndProjectPaths(t *testing.T) {
	debian, err := parseDoctorURL("https://repo.example/dists/stable/main/binary-amd64/Packages.xz")
	if err != nil {
		t.Fatal(err)
	}
	index, err := doctorIndexURL(debian, "deb", DoctorRequest{})
	if err != nil || index.String() != debian.String() {
		t.Fatalf("compressed index=%v err=%v", index, err)
	}
	python, err := parseDoctorURL("https://repo.example/simple/old/")
	if err != nil {
		t.Fatal(err)
	}
	index, err = doctorIndexURL(python, "pypi", DoctorRequest{Project: "demo"})
	if err != nil || index.String() != "https://repo.example/simple/demo/" {
		t.Fatalf("project index=%v err=%v", index, err)
	}
}

func TestDoctorInspectsFlatDebianRepository(t *testing.T) {
	packages := []byte("Package: demo\nVersion: 1\nArchitecture: all\nFilename: ./demo.deb\nSize: 1\nSHA256: " + strings.Repeat("a", 64) + "\n")
	fetcher := doctorMemoryFetcher{responses: map[string]source.Response{
		"https://repo.example/flat/Packages": {StatusCode: 200, Body: packages},
		"https://repo.example/flat/demo.deb": {StatusCode: 404},
	}}
	result, err := Doctor(context.Background(), DoctorRequest{URL: "https://repo.example/flat/Packages", Format: "deb", Fetcher: fetcher})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := doctorFindingByCode(result.Findings, "scope.repository-base"); ok {
		t.Fatalf("flat repository base was not inferred: %#v", result.Findings)
	}
	if _, ok := doctorFindingByCode(result.Findings, "reference.missing"); !ok {
		t.Fatalf("flat repository artifact was not checked: %#v", result.Findings)
	}
}

func TestDoctorDistinguishesMissingAndUnavailableReferences(t *testing.T) {
	index := []byte("apiVersion: v1\nentries:\n  demo:\n    - name: demo\n      version: 1.2.3\n      digest: " + strings.Repeat("a", 64) + "\n      urls: [charts/demo-1.2.3.tgz]\n")
	fetcher := doctorMemoryFetcher{responses: map[string]source.Response{
		"https://repo.example/index.yaml":            {StatusCode: 200, Body: index},
		"https://repo.example/charts/demo-1.2.3.tgz": {StatusCode: 404},
	}}
	result, err := Doctor(context.Background(), DoctorRequest{URL: "https://repo.example", Format: "helm", Fetcher: fetcher})
	if err != nil {
		t.Fatal(err)
	}
	if finding, ok := doctorFindingByCode(result.Findings, "reference.missing"); !ok || finding.Severity != "error" {
		t.Fatalf("missing findings %#v", result.Findings)
	}
	delete(fetcher.responses, "https://repo.example/charts/demo-1.2.3.tgz")
	result, err = Doctor(context.Background(), DoctorRequest{URL: "https://repo.example", Format: "helm", Fetcher: fetcher})
	if err != nil {
		t.Fatal(err)
	}
	if finding, ok := doctorFindingByCode(result.Findings, "reference.unavailable"); !ok || finding.Severity != "warning" {
		t.Fatalf("unavailable findings %#v", result.Findings)
	}
}

func TestDoctorRejectsUnsafeURLAndHonorsCancellation(t *testing.T) {
	fetcher := doctorMemoryFetcher{responses: map[string]source.Response{}}
	if _, err := Doctor(context.Background(), DoctorRequest{URL: "http://127.0.0.1/repo", Format: "helm", Fetcher: fetcher}); err == nil {
		t.Fatal("doctor accepted an unsafe URL")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Doctor(ctx, DoctorRequest{URL: "https://repo.example/index.yaml", Format: "helm", Fetcher: fetcher}); err == nil {
		t.Fatal("doctor ignored cancellation")
	}
}

func TestDoctorPropagatesArtifactCancellation(t *testing.T) {
	fetcher := &cancelArtifactFetcher{index: source.Response{
		StatusCode: 200,
		Body:       []byte("apiVersion: v1\nentries:\n  demo:\n    - name: demo\n      version: 1.2.3\n      digest: " + strings.Repeat("a", 64) + "\n      urls: [demo-1.2.3.tgz]\n"),
	}}
	_, err := Doctor(context.Background(), DoctorRequest{URL: "https://repo.example/index.yaml", Format: "helm", Fetcher: fetcher})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("artifact cancellation error = %v", err)
	}
}

func TestDoctorCumulativeBudgetIncludesOversizedAttempts(t *testing.T) {
	var index strings.Builder
	index.WriteString("apiVersion: v1\nentries:\n  demo:\n")
	for version := 0; version < 4; version++ {
		fmt.Fprintf(&index, "    - name: demo\n      version: 1.0.%d\n      digest: %s\n      urls: [demo-1.0.%d.tgz]\n", version, strings.Repeat("a", 64), version)
	}
	fetcher := &limitArtifactFetcher{index: source.Response{StatusCode: 200, Body: []byte(index.String())}}
	result, err := Doctor(context.Background(), DoctorRequest{URL: "https://repo.example/index.yaml", Format: "helm", MaxArtifacts: 4, Fetcher: fetcher})
	if err != nil {
		t.Fatal(err)
	}
	if fetcher.calls != 3 {
		t.Fatalf("doctor made %d fetches after exhausting its byte budget", fetcher.calls)
	}
	if _, ok := doctorFindingByCode(result.Findings, "scope.byte-limit"); !ok {
		t.Fatalf("byte-limit finding missing: %#v", result.Findings)
	}
}

type doctorMemoryFetcher struct {
	responses map[string]source.Response
}

type cancelArtifactFetcher struct {
	index source.Response
	calls int
}

type limitArtifactFetcher struct {
	index source.Response
	calls int
}

func (fetcher *limitArtifactFetcher) Fetch(context.Context, string, int64) (source.Response, error) {
	fetcher.calls++
	if fetcher.calls == 1 {
		return fetcher.index, nil
	}
	return source.Response{}, source.ErrLimit
}

func (fetcher *cancelArtifactFetcher) Fetch(context.Context, string, int64) (source.Response, error) {
	fetcher.calls++
	if fetcher.calls == 1 {
		return fetcher.index, nil
	}
	return source.Response{}, context.Canceled
}

func (fetcher doctorMemoryFetcher) Fetch(ctx context.Context, rawURL string, maximum int64) (source.Response, error) {
	if err := ctx.Err(); err != nil {
		return source.Response{}, err
	}
	response, exists := fetcher.responses[rawURL]
	if !exists {
		return source.Response{}, errors.New("unavailable")
	}
	if int64(len(response.Body)) > maximum {
		return source.Response{}, errors.New("response exceeds limit")
	}
	if response.URL == "" {
		response.URL = rawURL
	}
	return response, nil
}

func readDoctorFixture(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func hasDoctorErrors(findings []DoctorFinding) bool {
	for _, finding := range findings {
		if finding.Severity == "error" {
			return true
		}
	}
	return false
}

func doctorFindingByCode(findings []DoctorFinding, code string) (DoctorFinding, bool) {
	for _, finding := range findings {
		if finding.Code == code {
			return finding, true
		}
	}
	return DoctorFinding{}, false
}
