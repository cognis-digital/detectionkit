package listing

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanAndRender(t *testing.T) {
	dir := t.TempDir()

	good := `{"id":"a","title":"Good","severity":"low","logsource":{"product":"p"},"condition":{"selector":{"field":"f","operator":"equals","value":"v"}}}`
	bad := `{"id":"b","title":"Bad","severity":"spicy","logsource":{"product":"p"},"condition":{"selector":{"field":"f","operator":"equals","value":"v"}}}`
	junk := `{ not json`

	write(t, dir, "a.json", good)
	write(t, dir, "b.json", bad)
	write(t, dir, "c.json", junk)

	entries, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(entries))
	}

	byFile := map[string]Entry{}
	for _, e := range entries {
		byFile[e.File] = e
	}

	if !byFile["a.json"].Valid {
		t.Error("a.json should be valid")
	}
	if len(byFile["a.json"].Targets) != 3 {
		t.Errorf("a.json targets = %d, want 3", len(byFile["a.json"].Targets))
	}
	if byFile["b.json"].Valid {
		t.Error("b.json (bad severity) should be invalid")
	}
	if byFile["c.json"].Valid {
		t.Error("c.json (junk) should be invalid")
	}

	out := Render(entries)
	if !strings.Contains(out, "3 rule(s), 1 valid") {
		t.Errorf("render summary missing/wrong:\n%s", out)
	}
	if !strings.Contains(out, "TARGETS") {
		t.Error("render missing header")
	}
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
