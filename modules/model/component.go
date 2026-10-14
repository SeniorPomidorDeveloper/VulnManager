package model

type (
	PURL          string
	PURLRaw       string
	ComponentType string
)

type Component struct {
	PURL      PURL
	Type      ComponentType
	Namespace string
	Name      string
	Version   string
}

func (c Component) IsZero() bool {
	return c == Component{}
}
