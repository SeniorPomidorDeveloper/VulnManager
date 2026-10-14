package blocks

import (
	"context"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/cvss"
	"vulnmanager/services/normalize/internal/normalizers"
)

const (
	CVSSNormalizer normalizers.NormalizerID = "cvss"

	cvssVersion normalizers.NormalizerVersion = "1"
)

const codeInvalidCVSS = "invalid_cvss"

type cvssNormalizer struct{}

func NewCVSS() normalizers.Normalizer {
	return cvssNormalizer{}
}

func (cvssNormalizer) ID() normalizers.NormalizerID {
	return CVSSNormalizer
}

func (cvssNormalizer) Version() normalizers.NormalizerVersion {
	return cvssVersion
}

func (cvssNormalizer) Applies(model.Kind) bool {
	return true
}

func (cvssNormalizer) Normalize(_ context.Context, finding *model.Finding) error {
	finding.CVSS = nil
	for _, candidate := range finding.CVSSRaw {
		result, err := cvss.Parse(string(candidate.Vector))
		if err != nil {
			if !finding.Diagnostics.Has(codeInvalidCVSS) {
				finding.Diagnostics = finding.Diagnostics.Append(model.DiagLevelWarn, codeInvalidCVSS, err.Error())
			}
			continue
		}
		finding.CVSS = append(finding.CVSS, model.CVSSScore{
			Source:    candidate.Source,
			Version:   model.CVSSVersion(result.Version),
			Vector:    model.CVSSVector(result.Vector),
			BaseScore: model.Score(result.BaseScore),
		})
	}
	return nil
}

func CVSS() (normalizers.Normalizer, error) {
	return NewCVSS(), nil
}
