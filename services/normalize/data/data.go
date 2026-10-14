package data

import "embed"

//go:embed severity_maps tool_profiles vuln_id_formats.yaml path_rules.yaml
var FS embed.FS
