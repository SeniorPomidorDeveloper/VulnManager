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
)

type Catalog struct {
	Scales   normalizers.SeverityScales
	Profiles normalizers.ProfileSpec
}

type scaleFile struct {
	Scale map[string]string `yaml:"scale"`
}

type profileFile struct {
	Chain []string `yaml:"chain"`
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
	catalog := Catalog{Scales: normalizers.SeverityScales{ByTool: map[model.ToolName]normalizers.SeverityScale{}}}
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
