package model

type (
	TenantID    string
	ProductID   string
	ContextID   string
	ScopeKey    string
	FindingID   string
	ImportRunID string
	IssueID     string
	AssetID     string
	AdvisoryID  string
	ScanID      string
)

func (id TenantID) IsEmpty() bool {
	return id == ""
}

func (id ProductID) IsEmpty() bool {
	return id == ""
}
