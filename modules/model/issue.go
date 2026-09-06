package model

import "time"

type Issue struct {
	ID          string
	Scope       Scope
	AssetID     string
	ObjectKind  Kind
	AdvisoryID  string
	CWEID       string
	FirstSeenAt time.Time
}
