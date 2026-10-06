package model

import "time"

type Issue struct {
	ID          IssueID
	Scope       Scope
	AssetID     AssetID
	ObjectKind  Kind
	AdvisoryID  AdvisoryID
	CWEID       string
	FirstSeenAt time.Time
}
