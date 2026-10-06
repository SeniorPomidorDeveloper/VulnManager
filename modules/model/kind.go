package model

const unknownName = "unknown"

type named interface {
	String() string
}

func indexByName[T named](values ...T) map[string]T {
	index := make(map[string]T, len(values))
	for _, v := range values {
		index[v.String()] = v
	}
	return index
}

type Kind struct {
	name string
}

var (
	KindUnknown   = Kind{}
	KindSAST      = Kind{name: "sast"}
	KindDAST      = Kind{name: "dast"}
	KindSCA       = Kind{name: "sca"}
	KindSecret    = Kind{name: "secret"}
	KindIaC       = Kind{name: "iac"}
	KindContainer = Kind{name: "container"}
)

var kindByName = indexByName(KindUnknown, KindSAST, KindDAST, KindSCA, KindSecret, KindIaC, KindContainer)

func (k Kind) String() string {
	if k.name == "" {
		return unknownName
	}
	return k.name
}

func ParseKind(s string) (Kind, error) {
	if k, ok := kindByName[s]; ok {
		return k, nil
	}
	return KindUnknown, ErrUnknownKind
}

type Severity struct {
	name string
}

var (
	SeverityUnknown  = Severity{}
	SeverityCritical = Severity{name: "critical"}
	SeverityHigh     = Severity{name: "high"}
	SeverityMedium   = Severity{name: "medium"}
	SeverityLow      = Severity{name: "low"}
	SeverityInfo     = Severity{name: "info"}
)

var severityByName = indexByName(SeverityUnknown, SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo)

func (s Severity) String() string {
	if s.name == "" {
		return unknownName
	}
	return s.name
}

func ParseSeverity(s string) (Severity, error) {
	if v, ok := severityByName[s]; ok {
		return v, nil
	}
	return SeverityUnknown, ErrUnknownSeverity
}
