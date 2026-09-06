package model

type Kind string

const (
	KindSAST      Kind = "sast"
	KindDAST      Kind = "dast"
	KindSCA       Kind = "sca"
	KindSecret    Kind = "secret"
	KindIaC       Kind = "iac"
	KindContainer Kind = "container"
	KindUnknown   Kind = "unknown"
)

func ParseKind(s string) (Kind, error) {
	switch Kind(s) {
	case KindSAST, KindDAST, KindSCA, KindSecret, KindIaC, KindContainer, KindUnknown:
		return Kind(s), nil
	default:
		return KindUnknown, ErrUnknownKind
	}
}

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
	SeverityUnknown  Severity = "unknown"
)
