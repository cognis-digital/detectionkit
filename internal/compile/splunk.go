package compile

import (
	"fmt"
	"strings"

	"github.com/cognis-digital/detectionkit/internal/rule"
)

// Splunk renders the rule as an SPL search string.
//
// The condition tree maps directly onto SPL boolean syntax. The search is
// prefixed with the log source as a sourcetype/source hint when available and
// is suffixed with a comment carrying rule metadata.
func Splunk(r *rule.Rule) (string, error) {
	var prefix []string
	if r.LogSource.Service != "" {
		prefix = append(prefix, fmt.Sprintf("source=%s", splunkValue(r.LogSource.Service)))
	}
	if r.LogSource.Product != "" {
		prefix = append(prefix, fmt.Sprintf("sourcetype=%s", splunkValue(r.LogSource.Product)))
	}

	body := splunkCondition(r.Condition)

	var search strings.Builder
	search.WriteString("search ")
	if len(prefix) > 0 {
		search.WriteString(strings.Join(prefix, " "))
		search.WriteString(" ")
	}
	search.WriteString(body)

	// Trailing rename/comment keeps the rule traceable in saved searches.
	search.WriteString(fmt.Sprintf(" | eval detection_id=%s, severity=%s",
		splunkValue(r.ID), splunkValue(strings.ToLower(r.Severity))))

	return search.String(), nil
}

// splunkCondition renders a condition node as an SPL boolean expression.
func splunkCondition(c rule.Condition) string {
	if c.IsLeaf() {
		return splunkSelector(*c.Selector)
	}
	joiner := " AND "
	if c.Combinator() == "or" {
		joiner = " OR "
	}
	parts := make([]string, 0, len(c.Children()))
	for _, ch := range c.Children() {
		parts = append(parts, splunkCondition(ch))
	}
	expr := strings.Join(parts, joiner)
	if len(parts) > 1 {
		return "(" + expr + ")"
	}
	return expr
}

// splunkSelector renders one selector as an SPL term.
func splunkSelector(s rule.Selector) string {
	switch s.Operator {
	case rule.OpEquals:
		return fmt.Sprintf("%s=%s", s.Field, splunkValue(s.Value))
	case rule.OpContains:
		return fmt.Sprintf("%s=%s", s.Field, splunkValue("*"+s.Value+"*"))
	case rule.OpRegex:
		return fmt.Sprintf("| regex %s=%s", s.Field, splunkValue(s.Value))
	case rule.OpIn:
		quoted := make([]string, len(s.Values))
		for i, v := range s.Values {
			quoted[i] = splunkValue(v)
		}
		return fmt.Sprintf("%s IN (%s)", s.Field, strings.Join(quoted, ", "))
	}
	return ""
}

// splunkValue quotes a value for SPL when it contains whitespace or special
// characters; bare alphanumerics and wildcards are left unquoted.
func splunkValue(v string) string {
	if v == "" {
		return `""`
	}
	bare := true
	for _, r := range v {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '_' || r == '-' || r == '.' || r == '*') {
			bare = false
			break
		}
	}
	if bare {
		return v
	}
	return `"` + strings.ReplaceAll(v, `"`, `\"`) + `"`
}
