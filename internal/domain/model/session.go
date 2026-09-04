package model

// SystemState represents the reactive lifecycle state of the SRun client.
type SystemState string

const (
	StateOffline        SystemState = "offline"
	StateProbing        SystemState = "probing"
	StateAuthenticating SystemState = "authenticating"
	StateOnline         SystemState = "online"
	StateSuspended      SystemState = "suspended"
)

// Session represents active user session information.
type Session struct {
	IsOnline      bool    `json:"is_online"`
	ClientIP      string  `json:"client_ip"`
	OnlineIP      string  `json:"online_ip"`
	UserName      string  `json:"user_name"`
	UserMac       string  `json:"user_mac"`
	UserBalance   float64 `json:"user_balance"`
	UsedBytes     int64   `json:"used_bytes"`
	AllBytes      int64   `json:"all_bytes"`
	OnlineTime    int64   `json:"online_time"`
	KeepaliveTime int64   `json:"keepalive_time"`
}
