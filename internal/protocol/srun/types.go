package srun

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// ChallengeResponse models response from /cgi-bin/get_challenge
type ChallengeResponse struct {
	Challenge string `json:"challenge"`
	ClientIP  string `json:"client_ip"`
	OnlineIP  string `json:"online_ip"`
	Res       string `json:"res"`
	Error     string `json:"error"`
	ErrorMsg  string `json:"error_msg"`
}

// PortalResponse models response from /cgi-bin/srun_portal
type PortalResponse struct {
	Error     string `json:"error"`
	ErrorMsg  string `json:"error_msg"`
	Res       string `json:"res"`
	SucMsg    string `json:"suc_msg"`
	ClientIP  string `json:"client_ip"`
	OnlineIP  string `json:"online_ip"`
	Ecode     any    `json:"ecode"`
}

// UserInfo models parsed user accounting and online status from /cgi-bin/rad_user_info
type UserInfo struct {
	IsAvailable   bool           `json:"is_available"`
	IsOnline      bool           `json:"is_online"`
	ClientIP      string         `json:"client_ip"`
	OnlineIP      string         `json:"online_ip"`
	UserName      string         `json:"user_name"`
	UserMac       string         `json:"user_mac"`
	UserBalance   float64        `json:"user_balance"`
	UsedBytes     int64          `json:"used_bytes"`
	AllBytes      int64          `json:"all_bytes"`
	BytesIn       int64          `json:"bytes_in"`
	BytesOut      int64          `json:"bytes_out"`
	KeepaliveTime int64          `json:"keepalive_time"`
	OnlineTime    int64          `json:"online_time"`
	Error         string         `json:"error,omitempty"`
	ErrorMsg      string         `json:"error_msg,omitempty"`
	RawData       map[string]any `json:"raw_data,omitempty"`
}

// LoginResult represents the outcome of an authentication attempt.
type LoginResult struct {
	Success  bool   `json:"success"`
	Error    string `json:"error"`
	ErrorMsg string `json:"error_msg"`
	ClientIP string `json:"client_ip"`
}

// InterfaceInfo contains network adapter details.
type InterfaceInfo struct {
	InterfaceName string `json:"name"`
	IP            string `json:"ip"`
	MAC           string `json:"mac"`
	IsUp          bool   `json:"is_up"`
	IsLoopback    bool   `json:"is_loopback"`
}

// InterfaceProbeResult models connectivity status for a specific network interface.
type InterfaceProbeResult struct {
	IP            string `json:"ip"`
	Label         string `json:"label"`
	InterfaceName string `json:"interface_name"`
	Reachable     bool   `json:"reachable"`
	StatusMessage string `json:"message"`
}

// GatewayProbeSummary encapsulates reachability results across all local adapters.
type GatewayProbeSummary struct {
	Gateway        string                 `json:"gateway"`
	ACID           string                 `json:"ac_id"`
	SelfService    string                 `json:"self_service"`
	ReachableCount int                    `json:"reachable_count"`
	Results        []InterfaceProbeResult `json:"results"`
}

// ExtractJSONP strips JSONP function wrapper `jQuery12345(...)` or `jsonp(...)` and returns pure JSON bytes.
func ExtractJSONP(raw string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty response")
	}

	start := strings.IndexByte(trimmed, '(')
	end := strings.LastIndexByte(trimmed, ')')

	if start >= 0 && end > start {
		inner := strings.TrimSpace(trimmed[start+1 : end])
		return []byte(inner), nil
	}

	// Already raw JSON
	if (strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}")) ||
		(strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]")) {
		return []byte(trimmed), nil
	}

	return nil, fmt.Errorf("response is not valid JSON or JSONP: %s", trimmed)
}

// ParseJSONP decodes a JSONP string into a target struct.
func ParseJSONP[T any](raw string) (*T, error) {
	b, err := ExtractJSONP(raw)
	if err != nil {
		return nil, err
	}

	var res T
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&res); err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %w (body: %s)", err, string(b))
	}
	return &res, nil
}
