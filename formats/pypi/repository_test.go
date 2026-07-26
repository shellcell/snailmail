package pypi

import (
	"strings"
	"testing"
)

func TestParsePEP691Indexes(t *testing.T) {
	projects, err := ParseSimpleIndex("application/vnd.pypi.simple.v1+json", []byte(`{"meta":{"api-version":"1.0"},"projects":[{"name":"Demo_Pkg"}]}`))
	if err != nil || len(projects) != 1 || projects[0].URL != "demo-pkg/" {
		t.Fatalf("projects=%#v err=%v", projects, err)
	}
	name, files, err := ParseSimpleProject("application/vnd.pypi.simple.v1+json", []byte(`{"meta":{"api-version":"1.1"},"name":"Demo_Pkg","files":[{"filename":"demo_pkg-1.2.3-py3-none-any.whl","url":"../../files/demo.whl","hashes":{"sha256":"`+strings.Repeat("a", 64)+`"}}]}`))
	if err != nil || name != "Demo_Pkg" || len(files) != 1 {
		t.Fatalf("name=%q files=%#v err=%v", name, files, err)
	}
}

func TestParseSimpleProjectRejectsUnsafeFilename(t *testing.T) {
	content := []byte(`{"meta":{"api-version":"1.0"},"name":"demo","files":[{"filename":"bad\nname.whl","url":"bad.whl","hashes":{}}]}`)
	if _, _, err := ParseSimpleProject("application/json", content); err == nil {
		t.Fatal("unsafe distribution filename was accepted")
	}
}

func TestParsePEP691RejectsMissingMembersAndMalformedVersions(t *testing.T) {
	for _, content := range []string{
		`{"meta":{"api-version":"1.0"}}`,
		`{"meta":{"api-version":"1.foo"},"projects":[]}`,
	} {
		if _, err := ParseSimpleIndex("application/json", []byte(content)); err == nil {
			t.Fatalf("malformed project index accepted: %s", content)
		}
	}
	for _, content := range []string{
		`{"meta":{"api-version":"1.0"},"name":"demo"}`,
		`{"meta":{"api-version":"1.0"},"name":"demo","files":[{"filename":"demo-1.whl","url":"demo.whl"}]}`,
	} {
		if _, _, err := ParseSimpleProject("application/json", []byte(content)); err == nil {
			t.Fatalf("malformed project page accepted: %s", content)
		}
	}
}

func TestParseSimpleIndexRejectsUnsafeNamesAndURLs(t *testing.T) {
	for _, content := range []string{
		`{"meta":{"api-version":"1.0"},"projects":[{"name":"bad name!"}]}`,
		`{"meta":{"api-version":"1.0"},"projects":[{"name":"demo","url":"https://user:secret@example.test/demo/"}]}`,
		`{"meta":{"api-version":"1.0"},"projects":[{"name":"demo","url":"other/"}]}`,
	} {
		if _, err := ParseSimpleIndex("application/json", []byte(content)); err == nil {
			t.Fatalf("unsafe project entry accepted: %s", content)
		}
	}
}
