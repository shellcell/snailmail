package helm

import (
	"strings"
	"testing"
)

func TestRepositoryIndexRejectsAliasesAndMultipleDocuments(t *testing.T) {
	for _, content := range []string{
		"apiVersion: v1\nentries: &entries {}\ncopy: *entries\n",
		"apiVersion: v1\nentries: {}\n---\napiVersion: v1\nentries: {}\n",
	} {
		if _, err := ParseRepositoryIndex([]byte(content)); err == nil {
			t.Fatalf("unsafe Helm index accepted: %q", content)
		}
	}
}

func TestRepositoryIndexRejectsUnsafeChartURL(t *testing.T) {
	content := "apiVersion: v1\nentries:\n  demo:\n    - name: demo\n      version: 1.2.3\n      digest: " + strings.Repeat("a", 64) + "\n      urls: [%2e%2e/secret.tgz]\n"
	if _, err := ParseRepositoryIndex([]byte(content)); err == nil {
		t.Fatal("unsafe Helm chart URL was accepted")
	}
}
