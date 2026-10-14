package parsers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"strconv"
	"strings"

	"vulnmanager/modules/model"
)

const (
	FormatSARIF FormatName = "sarif"

	sarifID      ParserID      = "sarif"
	sarifVersion ParserVersion = "1"

	sarifSpecVersion                    = "2.1.0"
	sarifDefaultLevel model.SeverityRaw = "warning"

	codeSARIFVersion  = "sarif_version"
	codeInvalidResult = "invalid_result"
)

type SARIF struct{}

type sarifLog struct {
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool struct {
		Driver struct {
			Rules []sarifRule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Results []json.RawMessage `json:"results"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	ShortDescription *sarifText `json:"shortDescription"`
	DefaultLevel     struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	Properties struct {
		SecuritySeverity json.RawMessage `json:"security-severity"`
	} `json:"properties"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex *int            `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine   int `json:"startLine"`
			StartColumn int `json:"startColumn"`
			EndLine     int `json:"endLine"`
			EndColumn   int `json:"endColumn"`
		} `json:"region"`
	} `json:"physicalLocation"`
}

type normalizedLocation struct {
	URI         string `json:"uri,omitempty"`
	StartLine   int    `json:"start_line,omitempty"`
	StartColumn int    `json:"start_column,omitempty"`
	EndLine     int    `json:"end_line,omitempty"`
	EndColumn   int    `json:"end_column,omitempty"`
}

func NewSARIF() SARIF {
	return SARIF{}
}

func (SARIF) ID() ParserID {
	return sarifID
}

func (SARIF) Version() ParserVersion {
	return sarifVersion
}

func (SARIF) Capabilities() Capabilities {
	return Capabilities{Formats: []FormatName{FormatSARIF}, Kinds: []model.Kind{model.KindSAST}}
}

func (SARIF) Parse(ctx context.Context, r io.Reader, _ ScanMeta) iter.Seq2[RawFinding, error] {
	return func(yield func(RawFinding, error) bool) {
		var log sarifLog
		if err := json.NewDecoder(r).Decode(&log); err != nil {
			yield(RawFinding{}, fmt.Errorf("decode sarif: %w", err))
			return
		}
		for _, run := range log.Runs {
			for _, raw := range run.Results {
				if err := ctx.Err(); err != nil {
					yield(RawFinding{}, err)
					return
				}
				finding := convertResult(raw, run.Tool.Driver.Rules)
				if log.Version != sarifSpecVersion {
					finding.Diagnostics = finding.Diagnostics.Append(
						model.DiagLevelWarn, codeSARIFVersion, "unexpected sarif version "+log.Version,
					)
				}
				if !yield(finding, nil) {
					return
				}
			}
		}
	}
}

func convertResult(raw json.RawMessage, rules []sarifRule) RawFinding {
	var result sarifResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return RawFinding{
			Kind:  model.KindSAST,
			Title: "unparsed result",
			Raw:   raw,
			Diagnostics: model.Diagnostics{}.Append(
				model.DiagLevelWarn, codeInvalidResult, err.Error(),
			),
		}
	}

	rule := lookupRule(result, rules)
	location, diagnostics := convertLocation(result.Locations)
	return RawFinding{
		ToolFindingID: findingID(result, location),
		Kind:          model.KindSAST,
		Title:         title(result, rule),
		Description:   result.Message.Text,
		SeverityRaw:   severity(result, rule),
		ScannerScore:  securityScore(rule.Properties.SecuritySeverity),
		Location:      location.json(),
		Raw:           raw,
		Diagnostics:   diagnostics,
	}
}

func lookupRule(result sarifResult, rules []sarifRule) sarifRule {
	if result.RuleIndex != nil && *result.RuleIndex >= 0 && *result.RuleIndex < len(rules) {
		return rules[*result.RuleIndex]
	}
	for _, rule := range rules {
		if rule.ID == result.RuleID {
			return rule
		}
	}
	return sarifRule{}
}

func securityScore(raw json.RawMessage) *model.Score {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		text = string(raw)
	}
	value, err := strconv.ParseFloat(strings.TrimSpace(text), 64)
	if err != nil {
		return nil
	}
	score := model.Score(value)
	return &score
}

func title(result sarifResult, rule sarifRule) string {
	switch {
	case rule.ShortDescription != nil && rule.ShortDescription.Text != "":
		return rule.ShortDescription.Text
	case rule.Name != "":
		return rule.Name
	case result.RuleID != "":
		return result.RuleID
	}
	return "unnamed finding"
}

func severity(result sarifResult, rule sarifRule) model.SeverityRaw {
	switch {
	case result.Level != "":
		return model.SeverityRaw(result.Level)
	case rule.DefaultLevel.Level != "":
		return model.SeverityRaw(rule.DefaultLevel.Level)
	}
	return sarifDefaultLevel
}

func (l normalizedLocation) json() json.RawMessage {
	if l == (normalizedLocation{}) {
		return nil
	}
	encoded, err := json.Marshal(l)
	if err != nil {
		return nil
	}
	return encoded
}

func convertLocation(locations []sarifLocation) (normalizedLocation, model.Diagnostics) {
	if len(locations) == 0 {
		return normalizedLocation{}, nil
	}
	physical := locations[0].PhysicalLocation
	uri := strings.TrimPrefix(physical.ArtifactLocation.URI, "file://")
	var diagnostics model.Diagnostics
	if strings.HasPrefix(uri, "/") {
		diagnostics = diagnostics.Append(model.DiagLevelWarn, codeAbsolutePath, "artifact uri is an absolute path")
	}
	return normalizedLocation{
		URI:         uri,
		StartLine:   physical.Region.StartLine,
		StartColumn: physical.Region.StartColumn,
		EndLine:     physical.Region.EndLine,
		EndColumn:   physical.Region.EndColumn,
	}, diagnostics
}

func findingID(result sarifResult, location normalizedLocation) model.ToolFindingID {
	return model.ToolFindingID(strings.Join([]string{
		result.RuleID, location.URI, strconv.Itoa(location.StartLine), strconv.Itoa(location.StartColumn),
	}, "|"))
}
