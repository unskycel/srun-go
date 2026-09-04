package bridge

// AccountDTO models saved account representation for the frontend.
type AccountDTO struct {
	Username    string `json:"username"`
	Remark      string `json:"remark"`
	HasPassword bool   `json:"has_password"`
	IsActive    bool   `json:"is_active"`
	AutoLogin   bool   `json:"auto_login"`
}

// ConfigDTO models the structured frontend configuration payload.
type ConfigDTO struct {
	Username      string       `json:"username"`
	HasPassword   bool         `json:"has_password"`
	Accounts      []AccountDTO `json:"accounts"`
	ActiveUser    string       `json:"active_user"`
	AutoLogin     bool         `json:"auto_login"`
	AutoReconnect bool         `json:"auto_reconnect"`
	AutoStart     bool         `json:"auto_start"`
	Sleeptime     int          `json:"sleeptime"`
	Gateway       string       `json:"gateway"`
	SelfService   string       `json:"self_service"`
	ActiveIP      *string      `json:"active_ip"`
	LocalIPs      []*string    `json:"local_ips"`
}

// IPSettingsDTO models settings and available IP interfaces.
type IPSettingsDTO struct {
	Available     []string  `json:"available"`
	Selected      []*string `json:"selected"`
	Active        *string   `json:"active"`
	Gateway       string    `json:"gateway"`
	SelfService   string    `json:"self_service"`
	AutoReconnect bool      `json:"auto_reconnect"`
	AutoStart     bool      `json:"auto_start"`
	Sleeptime     int       `json:"sleeptime"`
}

// UpdateSettingsDTO models incoming settings updates from the UI wizard.
type UpdateSettingsDTO struct {
	Gateway       string    `json:"gateway"`
	SelfService   string    `json:"self_service"`
	Selected      []*string `json:"selected"`
	Active        *string   `json:"active"`
	AutoReconnect *bool     `json:"auto_reconnect,omitempty"`
	AutoStart     *bool     `json:"auto_start,omitempty"`
	Sleeptime     *int      `json:"sleeptime,omitempty"`
}

// OnlineDataDTO models active session information for dashboard rendering.
type OnlineDataDTO struct {
	IsAvailable bool           `json:"is_available"`
	IsOnline    bool           `json:"is_online"`
	Data        map[string]any `json:"data"`
}

// LogEntryDTO models an individual log entry for the UI.
type LogEntryDTO struct {
	Timestamp string `json:"time"`
	Level     string `json:"level"`
	Message   string `json:"message"`
}
