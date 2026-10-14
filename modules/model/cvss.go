package model

type (
	CVSSSource    string
	CVSSVectorRaw string
	CVSSVector    string
	CVSSVersion   string
	Score         float64
)

type CVSSCandidate struct {
	Source CVSSSource
	Vector CVSSVectorRaw
}

type CVSSScore struct {
	Source    CVSSSource
	Version   CVSSVersion
	Vector    CVSSVector
	BaseScore Score
}
