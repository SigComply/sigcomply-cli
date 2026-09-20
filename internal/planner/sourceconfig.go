package planner

import (
	"fmt"

	"github.com/sigcomply/sigcomply-cli/internal/sources"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// SourceConfigWarnings reports keys under a `sources:` entry that the
// source does not read, and declared keys whose value is not a string.
//
// The project config loader runs with KnownFields(true), which catches a
// typo anywhere else in the file. It stops at the source key: the inner
// bag is a map[string]any by design, so `tenat_id`, or `role_arn` on an
// Azure source, produces no output at all — the run proceeds with the
// value silently ignored, and the operator's mental model of what was
// audited is wrong in a way nothing corrects.
//
// The type check is the other half, and the reason a key list alone
// would not be enough: sources.StringOpt returns "" for both a missing
// key and a wrong-typed one, so `project_id: 12345` (an unquoted YAML
// integer) reads as absent. That produces "project_id required" if the
// key is mandatory, and silence if it is not.
//
// Warning, never error. The `experimental:` hatch exists precisely so a
// newer config can carry keys an older CLI does not know, and the same
// tolerance belongs here: failing the run would make every forward-
// compatible config an outage. A source that declared no keys is never
// warned about, so a project-local plugin is unaffected.
func SourceConfigWarnings(cfg *spec.ProjectConfig) []string {
	if cfg == nil || len(cfg.Sources) == 0 {
		return nil
	}
	var out []string
	for _, id := range sortedKeys(cfg.Sources) {
		// A configured key may carry an instance suffix; the factory,
		// and therefore the key list, is registered under the base ID.
		base, _ := sources.SplitInstanceID(id)
		known := sources.ConfigKeys(base)
		if len(known) == 0 {
			continue
		}
		out = append(out, sourceKeyWarnings(id, cfg.Sources[id], known)...)
	}
	return out
}

func sourceKeyWarnings(id string, bag map[string]any, known []string) []string {
	set := make(map[string]struct{}, len(known))
	for _, k := range known {
		set[k] = struct{}{}
	}
	var out []string
	for _, key := range sortedKeys(bag) {
		if _, ok := set[key]; !ok {
			out = append(out, fmt.Sprintf("sources.%s: unrecognized key %q, so it was ignored; %s reads %v",
				id, key, id, known))
			continue
		}
		// A declared key with a non-string value reads as absent to
		// every factory in the tree, which is the silent half.
		if _, isString := bag[key].(string); !isString && bag[key] != nil {
			out = append(out, fmt.Sprintf("sources.%s: %q is %T, not a string, so it reads as unset; quote it (%s: \"%v\")",
				id, key, bag[key], key, bag[key]))
		}
	}
	return out
}
