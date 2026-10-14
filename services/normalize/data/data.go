package data

import "embed"

//go:embed severity_maps tool_profiles vuln_id_formats.yaml
var FS embed.FS
