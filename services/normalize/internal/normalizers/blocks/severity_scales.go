package blocks

import (
	"maps"

	"vulnmanager/modules/model"
)

type SeverityScale map[model.SeverityRaw]model.Severity

func LabelScale() SeverityScale {
	return SeverityScale{
		"critical":      model.SeverityCritical,
		"high":          model.SeverityHigh,
		"medium":        model.SeverityMedium,
		"moderate":      model.SeverityMedium,
		"low":           model.SeverityLow,
		"info":          model.SeverityInfo,
		"informational": model.SeverityInfo,
		"unknown":       model.SeverityUnknown,
	}
}

func SARIFLevelScale() SeverityScale {
	return SeverityScale{
		"error":   model.SeverityHigh,
		"warning": model.SeverityMedium,
		"note":    model.SeverityLow,
		"none":    model.SeverityInfo,
	}
}

func MergeScales(scales ...SeverityScale) SeverityScale {
	merged := SeverityScale{}
	for _, scale := range scales {
		maps.Copy(merged, scale)
	}
	return merged
}
