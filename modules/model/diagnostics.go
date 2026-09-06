package model

type DiagnosticLevel string

const (
	DiagLevelInfo DiagnosticLevel = "info"
	DiagLevelWarn DiagnosticLevel = "warn"
)

type Diagnostic struct {
	Level   DiagnosticLevel
	Code    string
	Message string
}

type Diagnostics []Diagnostic

func (d Diagnostics) Append(level DiagnosticLevel, code, message string) Diagnostics {
	return append(d, Diagnostic{Level: level, Code: code, Message: message})
}
