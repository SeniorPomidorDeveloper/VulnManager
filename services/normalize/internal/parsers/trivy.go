package parsers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"maps"
	"slices"
	"strings"

	"vulnmanager/modules/model"
)

const (
	FormatTrivyJSON FormatName = "trivy-json"

	trivyID      ParserID      = "trivy"
	trivyVersion ParserVersion = "1"

	trivySchemaVersion = 2

	codeTrivySchema          = "trivy_schema_version"
	codeInvalidVulnerability = "invalid_vulnerability"
	codeUnsupportedSection   = "unsupported_section"
)

type Trivy struct{}

type trivyReport struct {
	SchemaVersion int           `json:"SchemaVersion"`
	Results       []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target            string            `json:"Target"`
	Type              string            `json:"Type"`
	Vulnerabilities   []json.RawMessage `json:"Vulnerabilities"`
	Misconfigurations []json.RawMessage `json:"Misconfigurations"`
	Secrets           []json.RawMessage `json:"Secrets"`
}

type trivyVulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
	Description      string `json:"Description"`

	CVSS          map[string]trivyCVSS `json:"CVSS"`
	PkgIdentifier struct {
		PURL string `json:"PURL"`
	} `json:"PkgIdentifier"`
}

type trivyCVSS struct {
	V2Vector string `json:"V2Vector"`
	V3Vector string `json:"V3Vector"`
}

type trivyLocation struct {
	Target           string `json:"target"`
	PackageType      string `json:"package_type,omitempty"`
	Package          string `json:"package,omitempty"`
	InstalledVersion string `json:"installed_version,omitempty"`
	FixedVersion     string `json:"fixed_version,omitempty"`
	PURL             string `json:"purl,omitempty"`
}

func NewTrivy() Trivy {
	return Trivy{}
}

func (Trivy) ID() ParserID {
	return trivyID
}

func (Trivy) Version() ParserVersion {
	return trivyVersion
}

func (Trivy) Capabilities() Capabilities {
	return Capabilities{Formats: []FormatName{FormatTrivyJSON}, Kinds: []model.Kind{model.KindSCA}}
}

func (Trivy) Parse(ctx context.Context, r io.Reader, _ ScanMeta) iter.Seq2[RawFinding, error] {
	return func(yield func(RawFinding, error) bool) {
		var report trivyReport
		if err := json.NewDecoder(r).Decode(&report); err != nil {
			yield(RawFinding{}, fmt.Errorf("decode trivy report: %w", err))
			return
		}
		for _, result := range report.Results {
			for _, finding := range convertTrivyResult(result) {
				if err := ctx.Err(); err != nil {
					yield(RawFinding{}, err)
					return
				}
				if report.SchemaVersion != trivySchemaVersion {
					finding.Diagnostics = finding.Diagnostics.Append(
						model.DiagLevelWarn, codeTrivySchema, fmt.Sprintf("unexpected schema version %d", report.SchemaVersion),
					)
				}
				if !yield(finding, nil) {
					return
				}
			}
		}
	}
}

func convertTrivyResult(result trivyResult) []RawFinding {
	target := result.Target
	absolute := strings.HasPrefix(target, "/")
	var found []RawFinding
	for _, raw := range result.Vulnerabilities {
		finding := convertVulnerability(raw, target, result.Type)
		if absolute {
			finding.Diagnostics = finding.Diagnostics.Append(
				model.DiagLevelWarn, codeAbsolutePath, "target is an absolute path",
			)
		}
		found = append(found, finding)
	}
	return append(found, unsupportedSections(result, target)...)
}

func convertVulnerability(raw json.RawMessage, target, packageType string) RawFinding {
	var vulnerability trivyVulnerability
	if err := json.Unmarshal(raw, &vulnerability); err != nil {
		return RawFinding{
			Kind:  model.KindSCA,
			Title: "unparsed vulnerability",
			Raw:   raw,
			Diagnostics: model.Diagnostics{}.Append(
				model.DiagLevelWarn, codeInvalidVulnerability, err.Error(),
			),
		}
	}
	location, err := json.Marshal(trivyLocation{
		Target:           target,
		PackageType:      packageType,
		Package:          vulnerability.PkgName,
		InstalledVersion: vulnerability.InstalledVersion,
		FixedVersion:     vulnerability.FixedVersion,
		PURL:             vulnerability.PkgIdentifier.PURL,
	})
	if err != nil {
		location = nil
	}
	return RawFinding{
		ToolFindingID: model.ToolFindingID(strings.Join([]string{
			vulnerability.VulnerabilityID, vulnerability.PkgName, vulnerability.InstalledVersion, target,
		}, "|")),
		Kind:        model.KindSCA,
		Title:       vulnerabilityTitle(vulnerability),
		Description: vulnerability.Description,
		SeverityRaw: model.SeverityRaw(vulnerability.Severity),
		VulnIDRaw:   model.VulnIDRaw(vulnerability.VulnerabilityID),
		PURLRaw:     model.PURLRaw(vulnerability.PkgIdentifier.PURL),
		Location:    location,
		Raw:         raw,

		CVSSVectors: trivyCVSSCandidates(vulnerability.CVSS),
	}
}

func trivyCVSSCandidates(sources map[string]trivyCVSS) []model.CVSSCandidate {
	var candidates []model.CVSSCandidate
	for _, name := range slices.Sorted(maps.Keys(sources)) {
		for _, vector := range []string{sources[name].V3Vector, sources[name].V2Vector} {
			if vector != "" {
				candidates = append(candidates, model.CVSSCandidate{Source: model.CVSSSource(name), Vector: model.CVSSVectorRaw(vector)})
			}
		}
	}
	return candidates
}

func vulnerabilityTitle(vulnerability trivyVulnerability) string {
	switch {
	case vulnerability.Title != "":
		return vulnerability.Title
	case vulnerability.VulnerabilityID != "":
		return vulnerability.VulnerabilityID
	}
	return "unnamed vulnerability"
}

func unsupportedSections(result trivyResult, target string) []RawFinding {
	sections := []struct {
		name  string
		count int
	}{
		{"misconfigurations", len(result.Misconfigurations)},
		{"secrets", len(result.Secrets)},
	}
	var found []RawFinding
	for _, section := range sections {
		if section.count == 0 {
			continue
		}
		summary, err := json.Marshal(map[string]any{"target": target, "section": section.name, "count": section.count})
		if err != nil {
			continue
		}
		found = append(found, RawFinding{
			Title: "unsupported trivy section: " + section.name,
			Raw:   summary,
			Diagnostics: model.Diagnostics{}.Append(
				model.DiagLevelWarn, codeUnsupportedSection, fmt.Sprintf("%d %s skipped", section.count, section.name),
			),
		})
	}
	return found
}
