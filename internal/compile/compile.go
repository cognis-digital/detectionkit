// Package compile turns a neutral rule into a SIEM-specific dialect.
package compile

import (
	"fmt"
	"strings"

	"github.com/cognis-digital/detectionkit/internal/rule"
)

// Target names a supported compilation backend.
type Target string

const (
	TargetSigma   Target = "sigma"
	TargetElastic Target = "elastic"
	TargetSplunk  Target = "splunk"
)

// Targets lists every supported target, in stable order.
var Targets = []Target{TargetSigma, TargetElastic, TargetSplunk}

// Compile renders the rule to the given target. It assumes the rule has
// already passed Validate; it still guards against an empty target.
func Compile(r *rule.Rule, t Target) (string, error) {
	switch t {
	case TargetSigma:
		return Sigma(r)
	case TargetElastic:
		return Elastic(r)
	case TargetSplunk:
		return Splunk(r)
	default:
		return "", fmt.Errorf("unknown target %q (want one of: %s)", t, targetList())
	}
}

func targetList() string {
	s := make([]string, len(Targets))
	for i, t := range Targets {
		s[i] = string(t)
	}
	return strings.Join(s, ", ")
}
