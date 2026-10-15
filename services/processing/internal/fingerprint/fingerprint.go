package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"vulnmanager/modules/model"
)

type (
	StrategyID   string
	Version      int
	Level        string
	Value        string
	FindingField string
)

const (
	LevelToolUID    Level = "l0"
	LevelIdentity   Level = "l1"
	LevelStructural Level = "l2"
)

const (
	algorithm = "sha256"
	separator = ":"
)

type Fingerprint struct {
	Level    Level
	Strategy StrategyID
	Version  Version
	Value    Value
}

type Strategy interface {
	ID() StrategyID
	Level() Level
	Version() Version
	Fingerprint(finding model.Finding) (Fingerprint, bool)
}

func digest(strategy Strategy, fields ...FindingField) Fingerprint {
	hash := sha256.New()
	for _, field := range fields {
		hash.Write([]byte(strconv.Itoa(len(field))))
		hash.Write([]byte(separator))
		hash.Write([]byte(field))
	}
	value := strings.Join([]string{
		"v" + strconv.Itoa(int(strategy.Version())), string(strategy.Level()), algorithm, hex.EncodeToString(hash.Sum(nil)),
	}, separator)
	return Fingerprint{Level: strategy.Level(), Strategy: strategy.ID(), Version: strategy.Version(), Value: Value(value)}
}
