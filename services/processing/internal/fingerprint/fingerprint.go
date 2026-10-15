package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"vulnmanager/modules/model"
)

type (
	StrategyID string
	Version    int
	Level      string
	Value      string
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
	Level Level
	Value Value
}

type Strategy interface {
	ID() StrategyID
	Level() Level
	Version() Version
	Fingerprint(finding model.Finding) (Fingerprint, bool)
}

func digest(level Level, version Version, parts ...string) Fingerprint {
	hash := sha256.New()
	for _, part := range parts {
		hash.Write([]byte(strconv.Itoa(len(part))))
		hash.Write([]byte(separator))
		hash.Write([]byte(part))
	}
	value := strings.Join([]string{
		"v" + strconv.Itoa(int(version)), string(level), algorithm, hex.EncodeToString(hash.Sum(nil)),
	}, separator)
	return Fingerprint{Level: level, Value: Value(value)}
}
