package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCanonicalJSONSortsKeysWithoutHTMLEscaping(t *testing.T) {
	encoded, err := canonicalJSON(map[string]any{"z": "<value>", "a": 1})
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"a":1,"z":"<value>"}` {
		t.Fatalf("canonical JSON = %s", encoded)
	}
}

func TestLoadPlanRejectsUnknownAndDuplicateFields(t *testing.T) {
	for name, content := range map[string]string{
		"unknown":   `{"schema_version":5,"plan_id":"x","payload":{},"unknown":true}`,
		"duplicate": `{"schema_version":5,"plan_id":"x","plan_id":"y","payload":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "plan.json")
			if err := os.WriteFile(filename, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadPlan(filename); err == nil || (!strings.Contains(err.Error(), "unknown") && !strings.Contains(err.Error(), "duplicate")) {
				t.Fatalf("ambiguous plan error = %v", err)
			}
		})
	}
}
