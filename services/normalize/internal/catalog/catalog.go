package catalog

import (
	"fmt"
	"io/fs"
	"path"
	"strings"

	"gopkg.in/yaml.v3"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/normalizers"
)

const (
	scalesDir   = "severity_maps"
	profilesDir = "tool_profiles"
	defaultName = "default"
	fileSuffix  = ".yaml"
	formatsPath = "vuln_id_formats.yaml"
	pathsPath   = "path_rules.yaml"
)

type Catalog struct {
	Scales      normalizers.SeverityScales
	Profiles    normalizers.ProfileSpec
	VulnFormats []normalizers.VulnFormat
	PathRules   normalizers.PathRules
}

type scaleFile struct {
	Scale map[string]string `yaml:"scale"`
}

type profileFile struct {
	Chain []string `yaml:"chain"`
}

type pathRulesFile struct {
	Fields        []string `yaml:"fields"`
	StripPrefixes []string `yaml:"strip_prefixes"`
}

type formatsFile struct {
	Formats []struct {
		Source string `yaml:"source"`
		Prefix string `yaml:"prefix"`
		Body   string `yaml:"body"`
		Case   string `yaml:"case"`
	} `yaml:"formats"`
}

func Load(fsys fs.FS) (Catalog, error) {
	scales, err := loadDir(fsys, scalesDir, parseScale)
	if err != nil {
		return Catalog{}, err
	}
	profiles, err := loadDir(fsys, profilesDir, parseProfile)
	if err != nil {
		return Catalog{}, err
	}
	formats, err := loadFormats(fsys)
	if err != nil {
		return Catalog{}, err
	}
	pathRules, err := loadPathRules(fsys)
	if err != nil {
		return Catalog{}, err
	}
	catalog := Catalog{VulnFormats: formats, PathRules: pathRules, Scales: normalizers.SeverityScales{ByTool: map[model.ToolName]normalizers.SeverityScale{}}}
	catalog.Profiles.ByTool = map[model.ToolName][]normalizers.NormalizerID{}
	for name, scale := range scales {
		if name == defaultName {
			catalog.Scales.Default = scale
			continue
		}
		catalog.Scales.ByTool[model.ToolName(name)] = scale
	}
	for name, chain := range profiles {
		if name == defaultName {
			catalog.Profiles.Default = chain
			continue
		}
		catalog.Profiles.ByTool[model.ToolName(name)] = chain
	}
	if catalog.Scales.Default == nil {
		return Catalog{}, fmt.Errorf("%s/%s%s is required", scalesDir, defaultName, fileSuffix)
	}
	if catalog.Profiles.Default == nil {
		return Catalog{}, fmt.Errorf("%s/%s%s is required", profilesDir, defaultName, fileSuffix)
	}
	return catalog, nil
}

func loadDir[T any](fsys fs.FS, dir string, parse func([]byte) (T, error)) (map[string]T, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	loaded := make(map[string]T, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), fileSuffix) {
			continue
		}
		content, err := fs.ReadFile(fsys, path.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read %s/%s: %w", dir, entry.Name(), err)
		}
		value, err := parse(content)
		if err != nil {
			return nil, fmt.Errorf("%s/%s: %w", dir, entry.Name(), err)
		}
		loaded[strings.TrimSuffix(entry.Name(), fileSuffix)] = value
	}
	return loaded, nil
}

func decodeStrict(content []byte, into any) error {
	decoder := yaml.NewDecoder(strings.NewReader(string(content)))
	decoder.KnownFields(true)
	return decoder.Decode(into)
}

func parseScale(content []byte) (normalizers.SeverityScale, error) {
	var file scaleFile
	if err := decodeStrict(content, &file); err != nil {
		return nil, err
	}
	scale := make(normalizers.SeverityScale, len(file.Scale))
	for label, name := range file.Scale {
		severity, err := model.ParseSeverity(name)
		if err != nil {
			return nil, fmt.Errorf("label %q: %w", label, err)
		}
		scale[model.SeverityRaw(strings.ToLower(strings.TrimSpace(label)))] = severity
	}
	return scale, nil
}

func parseProfile(content []byte) ([]normalizers.NormalizerID, error) {
	var file profileFile
	if err := decodeStrict(content, &file); err != nil {
		return nil, err
	}
	chain := make([]normalizers.NormalizerID, len(file.Chain))
	for i, id := range file.Chain {
		chain[i] = normalizers.NormalizerID(id)
	}
	return chain, nil
}

func loadFormats(fsys fs.FS) ([]normalizers.VulnFormat, error) {
	content, err := fs.ReadFile(fsys, formatsPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", formatsPath, err)
	}
	var file formatsFile
	if err := decodeStrict(content, &file); err != nil {
		return nil, fmt.Errorf("%s: %w", formatsPath, err)
	}
	formats := make([]normalizers.VulnFormat, 0, len(file.Formats))
	seen := make(map[string]struct{}, len(file.Formats))
	for _, spec := range file.Formats {
		prefix := strings.ToUpper(spec.Prefix)
		if _, dup := seen[prefix]; dup {
			return nil, fmt.Errorf("%s: duplicate prefix %q", formatsPath, spec.Prefix)
		}
		seen[prefix] = struct{}{}
		format, err := normalizers.NewVulnFormat(
			model.VulnSource(spec.Source), spec.Prefix, spec.Body, normalizers.CaseRule(spec.Case),
		)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", formatsPath, err)
		}
		formats = append(formats, format)
	}
	return formats, nil
}

func loadPathRules(fsys fs.FS) (normalizers.PathRules, error) {
	content, err := fs.ReadFile(fsys, pathsPath)
	if err != nil {
		return normalizers.PathRules{}, fmt.Errorf("read %s: %w", pathsPath, err)
	}
	var file pathRulesFile
	if err := decodeStrict(content, &file); err != nil {
		return normalizers.PathRules{}, fmt.Errorf("%s: %w", pathsPath, err)
	}
	rules, err := normalizers.NewPathRules(file.Fields, file.StripPrefixes)
	if err != nil {
		return normalizers.PathRules{}, fmt.Errorf("%s: %w", pathsPath, err)
	}
	return rules, nil
}
