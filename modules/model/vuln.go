package model

type (
	VulnSource string
	VulnIDRaw  string
)

const VulnSourceUnknown VulnSource = "unknown"

type VulnID struct {
	Source VulnSource
	Value  string
}

func (v VulnID) IsZero() bool {
	return v == VulnID{}
}
