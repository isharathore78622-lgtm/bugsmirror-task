package main

// Company
type Org struct {
	ID   string
	Name string
}

// User - json names must match the paper exactly
type User struct {
	UserID string `json:"userId"`
	OrgID  string `json:"orgId"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	Token  string `json:"token"`
}

// App - the SDK uses AppKey to talk to us
type App struct {
	AppID    string `json:"appId"`
	Name     string `json:"name"`
	Platform string `json:"platform"`
	AppKey   string `json:"appKey"`
	OrgID    string `json:"-"` // internal only, not sent in response
}

// Alert - one threat found on one device
type Alert struct {
	ID         string `json:"id"`
	AppID      string `json:"appId"`
	DeviceID   string `json:"deviceId"`
	ThreatType string `json:"threatType"`
	Severity   int    `json:"severity"`
	Count      int    `json:"count"`
	Status     string `json:"status"`
	FirstSeen  string `json:"firstSeen"`
	LastSeen   string `json:"lastSeen"`
	ResolvedBy string `json:"resolvedBy"`

	OrgID string `json:"-"` // which company owns this alert
	Seq   int    `json:"-"` // goes up every time alert is touched, used for sorting
}
