package catalog_test

import (
	"errors"
	"testing"
	"testing/fstest"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/data"
	"vulnmanager/services/normalize/internal/catalog"
)

const pathsYAML = "fields: [uri]\nstrip_prefixes:\n  - /src/\n"

const formatsYAML = "formats:\n  - {source: cve, prefix: 'CVE-', body: '\\d+', case: upper}\n"

func fixture(scale, profile string) fstest.MapFS {
	return fstest.MapFS{
		"vuln_id_formats.yaml":       {Data: []byte(formatsYAML)},
		"path_rules.yaml":            {Data: []byte(pathsYAML)},
		"severity_maps/default.yaml": {Data: []byte(scale)},
		"severity_maps/newtool.yaml": {Data: []byte("scale:\n  Sev-1: critical\n")},
		"tool_profiles/default.yaml": {Data: []byte(profile)},
		"tool_profiles/newtool.yaml": {Data: []byte("chain: [severity, custom]\n")},
		"severity_maps/README.md":    {Data: []byte("ignored")},
	}
}

func TestLoad_ReadsDefaultsAndPerToolFiles(t *testing.T) {
	loaded, err := catalog.Load(fixture("scale:\n  HIGH: high\n", "chain: [severity]\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Scales.Default["high"] != model.SeverityHigh {
		t.Fatalf("default scale %v", loaded.Scales.Default)
	}
	if loaded.Scales.ByTool["newtool"]["sev-1"] != model.SeverityCritical {
		t.Fatalf("tool scale %v", loaded.Scales.ByTool)
	}
	if got := loaded.Profiles.ByTool["newtool"]; len(got) != 2 || got[1] != "custom" {
		t.Fatalf("tool profile %v", got)
	}
	if got := loaded.Profiles.Default; len(got) != 1 || got[0] != "severity" {
		t.Fatalf("default profile %v", got)
	}
}

func TestLoad_RejectsBrokenFiles(t *testing.T) {
	cases := map[string]struct {
		scale   string
		profile string
		wantErr error
	}{
		"unknown severity":    {"scale:\n  x: extreme\n", "chain: [severity]\n", model.ErrUnknownSeverity},
		"unknown scale field": {"scale: {}\nextra: 1\n", "chain: [severity]\n", nil},
		"unknown profile key": {"scale: {}\n", "chain: []\nextra: 1\n", nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := catalog.Load(fixture(c.scale, c.profile))
			if err == nil || (c.wantErr != nil && !errors.Is(err, c.wantErr)) {
				t.Fatalf("err=%v, want %v", err, c.wantErr)
			}
		})
	}
}

func TestLoad_RequiresDefaults(t *testing.T) {
	_, err := catalog.Load(fstest.MapFS{
		"vuln_id_formats.yaml":     {Data: []byte(formatsYAML)},
		"path_rules.yaml":          {Data: []byte(pathsYAML)},
		"severity_maps/other.yaml": {Data: []byte("scale: {}\n")},
		"tool_profiles/other.yaml": {Data: []byte("chain: []\n")},
	})
	if err == nil {
		t.Fatal("want error without default.yaml")
	}
}

func TestLoad_EmbeddedData(t *testing.T) {
	loaded, err := catalog.Load(data.FS)
	if err != nil {
		t.Fatalf("embedded data: %v", err)
	}
	if loaded.Scales.Default["error"] != model.SeverityHigh || len(loaded.Profiles.Default) == 0 || len(loaded.VulnFormats) == 0 {
		t.Fatalf("unexpected embedded catalog %+v", loaded)
	}
}

func TestLoad_RejectsBrokenVulnFormats(t *testing.T) {
	cases := map[string]string{
		"duplicate prefix": "formats:\n  - {source: a, prefix: 'X-', body: '.+', case: keep}\n  - {source: b, prefix: 'x-', body: '.+', case: keep}\n",
		"unknown case":     "formats:\n  - {source: a, prefix: 'X-', body: '.+', case: title}\n",
		"unknown field":    "formats:\n  - {source: a, prefix: 'X-', body: '.+', case: keep, extra: 1}\n",
	}
	for name, yamlText := range cases {
		t.Run(name, func(t *testing.T) {
			files := fixture("scale: {}\n", "chain: [severity]\n")
			files["vuln_id_formats.yaml"] = &fstest.MapFile{Data: []byte(yamlText)}
			if _, err := catalog.Load(files); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestLoad_RejectsBrokenPathRules(t *testing.T) {
	cases := map[string]string{
		"bad prefix":    "fields: [uri]\nstrip_prefixes: [src]\n",
		"unknown field": "fields: [uri]\nextra: 1\n",
	}
	for name, yamlText := range cases {
		t.Run(name, func(t *testing.T) {
			files := fixture("scale: {}\n", "chain: [severity]\n")
			files["path_rules.yaml"] = &fstest.MapFile{Data: []byte(yamlText)}
			if _, err := catalog.Load(files); err == nil {
				t.Fatal("want error")
			}
		})
	}
}
