package blocks

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/normalizers"
)

const (
	ComponentNormalizer normalizers.NormalizerID = "component"

	componentVersion normalizers.NormalizerVersion = "1"

	purlScheme = "pkg:"
	unreserved = "-._~"
)

const codeInvalidPURL = "invalid_purl"

var ErrInvalidPURL = errors.New("normalizers: invalid purl")

var nameRules = map[model.ComponentType]func(string) string{
	"npm":    strings.ToLower,
	"golang": strings.ToLower,
	"deb":    strings.ToLower,
	"pypi":   func(name string) string { return strings.ReplaceAll(strings.ToLower(name), "_", "-") },
}

var namespaceRules = map[model.ComponentType]func(string) string{
	"npm":    strings.ToLower,
	"golang": strings.ToLower,
	"deb":    strings.ToLower,
	"rpm":    strings.ToLower,
}

type componentNormalizer struct{}

func NewComponent() normalizers.Normalizer {
	return componentNormalizer{}
}

func (componentNormalizer) ID() normalizers.NormalizerID {
	return ComponentNormalizer
}

func (componentNormalizer) Version() normalizers.NormalizerVersion {
	return componentVersion
}

func (componentNormalizer) Applies(model.Kind) bool {
	return true
}

func (componentNormalizer) Normalize(_ context.Context, finding *model.Finding) error {
	finding.Component = model.Component{}
	raw := strings.TrimSpace(string(finding.PURLRaw))
	if raw == "" {
		return nil
	}
	component, err := parsePURL(raw)
	if err != nil {
		if !finding.Diagnostics.Has(codeInvalidPURL) {
			finding.Diagnostics = finding.Diagnostics.Append(model.DiagLevelWarn, codeInvalidPURL, err.Error())
		}
		return nil
	}
	finding.Component = component
	return nil
}

func Component() (normalizers.Normalizer, error) {
	return NewComponent(), nil
}

func parsePURL(raw string) (model.Component, error) {
	if len(raw) < len(purlScheme) || !strings.EqualFold(raw[:len(purlScheme)], purlScheme) {
		return model.Component{}, fmt.Errorf("%w: %q has no pkg: scheme", ErrInvalidPURL, raw)
	}
	rest, _, _ := strings.Cut(raw[len(purlScheme):], "#")
	rest, query, _ := strings.Cut(rest, "?")
	path, version, _ := strings.Cut(strings.TrimLeft(rest, "/"), "@")
	segments := strings.Split(path, "/")
	if len(segments) < 2 || slices.Contains(segments, "") {
		return model.Component{}, fmt.Errorf("%w: %q needs a type and a name", ErrInvalidPURL, raw)
	}
	decoded := make([]string, len(segments))
	for i, segment := range segments {
		value, err := url.PathUnescape(segment)
		if err != nil {
			return model.Component{}, fmt.Errorf("%w: %q: %w", ErrInvalidPURL, raw, err)
		}
		decoded[i] = value
	}
	decodedVersion, err := url.PathUnescape(version)
	if err != nil {
		return model.Component{}, fmt.Errorf("%w: %q: %w", ErrInvalidPURL, raw, err)
	}
	qualifiers, err := canonicalQualifiers(query)
	if err != nil {
		return model.Component{}, fmt.Errorf("%w: %q: %w", ErrInvalidPURL, raw, err)
	}
	return buildComponent(model.ComponentType(strings.ToLower(decoded[0])), decoded[1:], decodedVersion, qualifiers), nil
}

func buildComponent(kind model.ComponentType, parts []string, version, qualifiers string) model.Component {
	name := applyRule(nameRules, kind, parts[len(parts)-1])
	namespace := applyRule(namespaceRules, kind, strings.Join(parts[:len(parts)-1], "/"))
	return model.Component{
		PURL:      model.PURL(canonicalPURL(kind, namespace, name, version, qualifiers)),
		Type:      kind,
		Namespace: namespace,
		Name:      name,
		Version:   version,
	}
}

func applyRule(rules map[model.ComponentType]func(string) string, kind model.ComponentType, value string) string {
	if rule, ok := rules[kind]; ok {
		return rule(value)
	}
	return value
}

func canonicalQualifiers(query string) (string, error) {
	if query == "" {
		return "", nil
	}
	pairs := strings.Split(query, "&")
	encoded := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		key, value, found := strings.Cut(pair, "=")
		decoded, err := url.PathUnescape(value)
		if !found || key == "" || err != nil {
			return "", fmt.Errorf("bad qualifier %q", pair)
		}
		if decoded != "" {
			encoded = append(encoded, strings.ToLower(key)+"="+escapePURL(decoded))
		}
	}
	slices.Sort(encoded)
	return strings.Join(encoded, "&"), nil
}

func canonicalPURL(kind model.ComponentType, namespace, name, version, qualifiers string) string {
	var builder strings.Builder
	builder.WriteString(purlScheme + string(kind) + "/")
	if namespace != "" {
		for _, segment := range strings.Split(namespace, "/") {
			builder.WriteString(escapePURL(segment) + "/")
		}
	}
	builder.WriteString(escapePURL(name))
	if version != "" {
		builder.WriteString("@" + escapePURL(version))
	}
	if qualifiers != "" {
		builder.WriteString("?" + qualifiers)
	}
	return builder.String()
}

func escapePURL(value string) string {
	var builder strings.Builder
	for _, b := range []byte(value) {
		if isPURLSafe(b) {
			builder.WriteByte(b)
			continue
		}
		fmt.Fprintf(&builder, "%%%02X", b)
	}
	return builder.String()
}

func isPURLSafe(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' ||
		strings.IndexByte(unreserved+":", b) >= 0
}
