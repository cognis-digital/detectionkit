// Package listing scans a directory of rules and produces a coverage table.
package listing

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cognis-digital/detectionkit/internal/compile"
	"github.com/cognis-digital/detectionkit/internal/rule"
)

// Entry summarizes one rule file for the listing table.
type Entry struct {
	File     string
	ID       string
	Title    string
	Severity string
	Fields   int
	Valid    bool
	Targets  []compile.Target // targets that compiled cleanly
}

// Scan reads every *.json file in dir, parses and validates it, and checks
// which targets it compiles to. Files that fail to parse become invalid
// entries rather than aborting the whole scan.
func Scan(dir string) ([]Entry, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)

	var entries []Entry
	for _, path := range matches {
		base := filepath.Base(path)
		data, err := os.ReadFile(path)
		if err != nil {
			entries = append(entries, Entry{File: base, Title: "(read error)", Valid: false})
			continue
		}
		r, err := rule.Parse(data)
		if err != nil {
			entries = append(entries, Entry{File: base, Title: "(parse error)", Valid: false})
			continue
		}
		e := Entry{
			File:     base,
			ID:       r.ID,
			Title:    r.Title,
			Severity: r.Severity,
			Fields:   len(r.Fields()),
			Valid:    r.Validate() == nil,
		}
		for _, t := range compile.Targets {
			if _, cerr := compile.Compile(r, t); cerr == nil {
				e.Targets = append(e.Targets, t)
			}
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// Render returns the listing as a fixed-width text table.
func Render(entries []Entry) string {
	var b strings.Builder
	const hdr = "%-22s  %-30s  %-8s  %-6s  %-7s  %s\n"
	b.WriteString(fmt.Sprintf(hdr, "ID", "TITLE", "SEVERITY", "FIELDS", "VALID", "TARGETS"))
	b.WriteString(strings.Repeat("-", 96) + "\n")
	for _, e := range entries {
		valid := "yes"
		if !e.Valid {
			valid = "NO"
		}
		targets := make([]string, len(e.Targets))
		for i, t := range e.Targets {
			targets[i] = string(t)
		}
		b.WriteString(fmt.Sprintf(hdr,
			truncate(e.ID, 22),
			truncate(e.Title, 30),
			e.Severity,
			fmt.Sprintf("%d", e.Fields),
			valid,
			strings.Join(targets, ","),
		))
	}
	b.WriteString(fmt.Sprintf("\n%d rule(s), %d valid\n", len(entries), countValid(entries)))
	return b.String()
}

func countValid(entries []Entry) int {
	n := 0
	for _, e := range entries {
		if e.Valid {
			n++
		}
	}
	return n
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
