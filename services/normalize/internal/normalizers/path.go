package normalizers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"vulnmanager/modules/model"
)

const (
	PathNormalizer NormalizerID = "path"

	pathVersion NormalizerVersion = "1"

	wildcardSegment = "*"
	separator       = "/"
)

var ErrInvalidPathRules = errors.New("normalizers: invalid path rules")

type PathRules struct {
	fields   []string
	prefixes [][]string
}

type pathNormalizer struct {
	rules PathRules
}

func NewPathRules(fields, prefixes []string) (PathRules, error) {
	parsed := make([][]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		segments, err := prefixSegments(prefix)
		if err != nil {
			return PathRules{}, err
		}
		parsed = append(parsed, segments)
	}
	slices.SortStableFunc(parsed, func(a, b []string) int { return len(b) - len(a) })
	return PathRules{fields: slices.Clone(fields), prefixes: parsed}, nil
}

func prefixSegments(prefix string) ([]string, error) {
	if !strings.HasPrefix(prefix, separator) || !strings.HasSuffix(prefix, separator) || prefix == separator {
		return nil, fmt.Errorf("%w: prefix %q must look like /a/b/", ErrInvalidPathRules, prefix)
	}
	segments := strings.Split(strings.Trim(prefix, separator), separator)
	if slices.Contains(segments, "") {
		return nil, fmt.Errorf("%w: prefix %q has an empty segment", ErrInvalidPathRules, prefix)
	}
	return segments, nil
}

func (r PathRules) clean(value string) string {
	if value == "" {
		return value
	}
	value = strings.ReplaceAll(value, `\`, separator)
	if strings.HasPrefix(value, separator) {
		value = r.stripPrefix(value)
	}
	return path.Clean(value)
}

func (r PathRules) stripPrefix(value string) string {
	segments := strings.Split(strings.TrimPrefix(path.Clean(value), separator), separator)
	for _, prefix := range r.prefixes {
		if len(segments) > len(prefix) && matchesPrefix(segments, prefix) {
			return strings.Join(segments[len(prefix):], separator)
		}
	}
	return value
}

func matchesPrefix(segments, prefix []string) bool {
	for i, want := range prefix {
		if want != wildcardSegment && want != segments[i] {
			return false
		}
	}
	return true
}

func NewPath(rules PathRules) Normalizer {
	return pathNormalizer{rules: rules}
}

func (pathNormalizer) ID() NormalizerID {
	return PathNormalizer
}

func (pathNormalizer) Version() NormalizerVersion {
	return pathVersion
}

func (pathNormalizer) Applies(model.Kind) bool {
	return true
}

func (n pathNormalizer) Normalize(_ context.Context, finding *model.Finding) error {
	var location map[string]json.RawMessage
	if len(finding.Location) == 0 || json.Unmarshal(finding.Location, &location) != nil {
		return nil
	}
	changed := false
	for _, field := range n.rules.fields {
		var value string
		if raw, ok := location[field]; !ok || json.Unmarshal(raw, &value) != nil {
			continue
		}
		cleaned := n.rules.clean(value)
		if cleaned == value {
			continue
		}
		encoded, err := json.Marshal(cleaned)
		if err != nil {
			return fmt.Errorf("encode %s: %w", field, err)
		}
		location[field] = encoded
		changed = true
	}
	if !changed {
		return nil
	}
	encoded, err := json.Marshal(location)
	if err != nil {
		return fmt.Errorf("encode location: %w", err)
	}
	finding.Location = encoded
	return nil
}
