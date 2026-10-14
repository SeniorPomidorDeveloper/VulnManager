package normalizers

import (
	"context"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/cvss"
)

const (
	CVSSNormalizer NormalizerID = "cvss"

	cvssVersion NormalizerVersion = "1"
)

const codeInvalidCVSS = "invalid_cvss"

type cvssNormalizer struct{}

func NewCVSS() Normalizer {
	return cvssNormalizer{}
}

func (cvssNormalizer) ID() NormalizerID {
	return CVSSNormalizer
}

func (cvssNormalizer) Version() NormalizerVersion {
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

func cvssStep() (Normalizer, error) {
	return NewCVSS(), nil
}
