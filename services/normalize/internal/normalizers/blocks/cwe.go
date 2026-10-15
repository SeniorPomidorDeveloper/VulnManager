package blocks

import (
	"context"
	"regexp"
	"slices"
	"strconv"

	"vulnmanager/modules/model"
	"vulnmanager/services/normalize/internal/normalizers"
)

const (
	CWENormalizer normalizers.NormalizerID = "cwe"

	cweVersion normalizers.NormalizerVersion = "1"

	cwePrefix = "CWE-"
)

const codeInvalidCWE = "invalid_cwe"

var cwePattern = regexp.MustCompile(`(?i)cwe[-_/ :]*0*(\d+)`)

type cweNormalizer struct{}

func NewCWE() normalizers.Normalizer {
	return cweNormalizer{}
}

func (cweNormalizer) ID() normalizers.NormalizerID {
	return CWENormalizer
}

func (cweNormalizer) Version() normalizers.NormalizerVersion {
	return cweVersion
}

func (cweNormalizer) Applies(model.Kind) bool {
	return true
}

func (cweNormalizer) Normalize(_ context.Context, finding *model.Finding) error {
	numbers := make([]int, 0, len(finding.CWERaw))
	for _, raw := range finding.CWERaw {
		found := cwePattern.FindAllStringSubmatch(string(raw), -1)
		if len(found) == 0 && !finding.Diagnostics.Has(codeInvalidCWE) {
			finding.Diagnostics = finding.Diagnostics.Append(model.DiagLevelWarn, codeInvalidCWE, "no CWE number in "+string(raw))
		}
		for _, match := range found {
			if number, err := strconv.Atoi(match[1]); err == nil && number > 0 {
				numbers = append(numbers, number)
			}
		}
	}
	slices.Sort(numbers)
	numbers = slices.Compact(numbers)
	finding.CWE = nil
	for _, number := range numbers {
		finding.CWE = append(finding.CWE, model.CWEName(cwePrefix+strconv.Itoa(number)))
	}
	return nil
}

func CWE() (normalizers.Normalizer, error) {
	return NewCWE(), nil
}
