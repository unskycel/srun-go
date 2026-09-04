package srun

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"srun/internal/protocol/codec"
)

const (
	EncTypePortal = "srun_bx1"
	EncTypeDM     = "1"
	DefaultDomain = "@"
	UserAgent     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

// Client handles SRun authentication lifecycle endpoints.
type Client struct {
	Host       string
	ACID       string
	LocalIP    string
	HTTPClient *http.Client
}

// NewClient creates a new SRun Client instance.
func NewClient(host, acid, localIP string) *Client {
	cleanHost := strings.TrimSpace(host)
	cleanHost = strings.TrimPrefix(cleanHost, "http://")
	cleanHost = strings.TrimPrefix(cleanHost, "https://")
	cleanHost = strings.TrimRight(cleanHost, "/")

	if acid == "" {
		acid = "1"
	}

	return &Client{
		Host:       cleanHost,
		ACID:       acid,
		LocalIP:    localIP,
		HTTPClient: NewHTTPClient(localIP, 10*time.Second, true),
	}
}

// GetChallenge queries the SRun portal challenge token for a given username and client IP.
func (c *Client) GetChallenge(ctx context.Context, username, ip string) (*ChallengeResponse, error) {
	cb := fmt.Sprintf("jQuery%d", time.Now().UnixNano())
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	params := url.Values{}
	params.Set("callback", cb)
	params.Set("username", username)
	params.Set("ip", ip)
	params.Set("_", ts)

	reqURL := fmt.Sprintf("http://%s/cgi-bin/get_challenge?%s", c.Host, params.Encode())
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create challenge request: %w", err)
	}
	req.Header.Set("User-Agent", UserAgent)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute challenge request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read challenge response: %w", err)
	}

	res, err := ParseJSONP[ChallengeResponse](string(body))
	if err != nil {
		return nil, fmt.Errorf("failed to parse challenge JSONP: %w", err)
	}

	if res.Challenge == "" {
		return nil, fmt.Errorf("empty challenge received: res=%s, error=%s", res.Res, res.Error)
	}

	return res, nil
}

// SrunInfoPayload defines the canonical payload structure required by SRun gateway C/JSON parsers.
type SrunInfoPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
	IP       string `json:"ip"`
	ACID     string `json:"acid"`
	EncVer   string `json:"enc_ver"`
}

// Login executes full SRun Portal authentication.
func (c *Client) Login(ctx context.Context, username, password string) (*PortalResponse, error) {
	cleanUser := strings.TrimSpace(username)
	if cleanUser == "" || password == "" {
		return nil, fmt.Errorf("username and password cannot be empty")
	}

	challengeRes, err := c.GetChallenge(ctx, cleanUser, c.LocalIP)
	if err != nil {
		return nil, fmt.Errorf("challenge retrieval failed: %w", err)
	}

	token := challengeRes.Challenge
	clientIP := challengeRes.ClientIP
	if clientIP == "" {
		clientIP = challengeRes.OnlineIP
	}
	if clientIP == "" {
		clientIP = c.LocalIP
	}
	if clientIP == "" {
		if uInfo, err := c.GetUserInfo(ctx); err == nil && uInfo.ClientIP != "" {
			clientIP = uInfo.ClientIP
		}
	}

	md5Hmac := codec.HmacMd5Hex(token, password)

	infoPayload := SrunInfoPayload{
		Username: cleanUser,
		Password: password,
		IP:       clientIP,
		ACID:     c.ACID,
		EncVer:   EncTypePortal,
	}

	infoParam, err := codec.GenerateInfo(infoPayload, token)
	if err != nil {
		return nil, fmt.Errorf("failed to generate info parameter: %w", err)
	}

	chksum := codec.GenerateChecksum(token, cleanUser, md5Hmac, c.ACID, clientIP, "200", EncTypeDM, infoParam)

	cb := fmt.Sprintf("jQuery%d", time.Now().UnixNano())
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	params := url.Values{}
	params.Set("callback", cb)
	params.Set("action", "login")
	params.Set("username", cleanUser)
	params.Set("password", "{MD5}"+md5Hmac)
	params.Set("ac_id", c.ACID)
	params.Set("ip", clientIP)
	params.Set("chksum", chksum)
	params.Set("info", infoParam)
	params.Set("n", "200")
	params.Set("type", EncTypeDM)
	params.Set("os", "Windows 10")
	params.Set("name", "Windows")
	params.Set("double_stack", "0")
	params.Set("_", ts)

	reqURL := fmt.Sprintf("http://%s/cgi-bin/srun_portal?%s", c.Host, params.Encode())
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create portal login request: %w", err)
	}
	req.Header.Set("User-Agent", UserAgent)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("portal login request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read portal response: %w", err)
	}

	portalRes, err := ParseJSONP[PortalResponse](string(body))
	if err != nil {
		return nil, fmt.Errorf("failed to parse portal login response: %w", err)
	}

	return portalRes, nil
}

// Logout executes standard SRun portal logout with automatic DM fallback.
func (c *Client) Logout(ctx context.Context, username string) (*PortalResponse, error) {
	// First probe active session to obtain true online IP
	userCtx, userCancel := context.WithTimeout(ctx, 3*time.Second)
	info, _ := c.GetUserInfo(userCtx)
	userCancel()

	var logoutIP string
	var logoutUser = username

	if info != nil {
		if !info.IsOnline && info.IsAvailable {
			return &PortalResponse{
				Error:    "ok",
				SucMsg:   "already logged out",
				ClientIP: info.ClientIP,
			}, nil
		}
		if info.OnlineIP != "" {
			logoutIP = info.OnlineIP
		} else if info.ClientIP != "" {
			logoutIP = info.ClientIP
		}
		if info.UserName != "" {
			logoutUser = info.UserName
		}
	}

	if logoutIP == "" {
		logoutIP = c.LocalIP
	}

	cb := fmt.Sprintf("jQuery%d", time.Now().UnixNano())
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	params := url.Values{}
	params.Set("callback", cb)
	params.Set("action", "logout")
	params.Set("username", logoutUser)
	params.Set("ac_id", c.ACID)
	params.Set("ip", logoutIP)
	params.Set("_", ts)

	reqURL := fmt.Sprintf("http://%s/cgi-bin/srun_portal?%s", c.Host, params.Encode())
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)

	resp, err := c.HTTPClient.Do(req)
	var portalErr error
	var portalRes *PortalResponse

	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		portalRes, portalErr = ParseJSONP[PortalResponse](string(body))
	}

	// If portal logout returned success or not_online_error, return directly
	if portalRes != nil && (portalRes.Error == "ok" || strings.Contains(portalRes.Error, "not_online")) {
		return portalRes, nil
	}

	// Fallback to DM logout
	dmRes, dmErr := c.LogoutDM(ctx, logoutUser, logoutIP)
	if dmErr == nil && dmRes != nil {
		return dmRes, nil
	}

	if portalRes != nil {
		return portalRes, nil
	}

	if portalErr != nil {
		return nil, portalErr
	}
	return nil, err
}

// LogoutDM performs classic DM logout fallback via `/cgi-bin/rad_user_dm`.
func (c *Client) LogoutDM(ctx context.Context, username, ip string) (*PortalResponse, error) {
	cb := fmt.Sprintf("jQuery%d", time.Now().UnixNano())
	nowMs := strconv.FormatInt(time.Now().UnixMilli(), 10)
	sign := codec.DMSign(username, ip, nowMs)

	params := url.Values{}
	params.Set("callback", cb)
	params.Set("time", nowMs)
	params.Set("username", username)
	params.Set("ip", ip)
	params.Set("sign", sign)
	params.Set("_", nowMs)

	reqURL := fmt.Sprintf("http://%s/cgi-bin/rad_user_dm?%s", c.Host, params.Encode())
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	resStr := string(body)
	if strings.Contains(resStr, "not_online") || strings.Contains(resStr, "ok") {
		return &PortalResponse{
			Error:    "ok",
			SucMsg:   "dm logout successful",
			ClientIP: ip,
		}, nil
	}

	dmParsed, err := ParseJSONP[PortalResponse](resStr)
	if err == nil && (dmParsed.Error == "ok" || strings.Contains(dmParsed.Error, "not_online")) {
		return dmParsed, nil
	}

	return nil, fmt.Errorf("dm logout response: %s", resStr)
}

// GetUserInfo queries user online accounting and traffic stats from `/cgi-bin/rad_user_info`.
func (c *Client) GetUserInfo(ctx context.Context) (*UserInfo, error) {
	cb := fmt.Sprintf("jQuery%d", time.Now().UnixNano())
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	params := url.Values{}
	params.Set("callback", cb)
	params.Set("ip", c.LocalIP)
	params.Set("_", ts)

	reqURL := fmt.Sprintf("http://%s/cgi-bin/rad_user_info?%s", c.Host, params.Encode())
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return &UserInfo{IsAvailable: false}, err
	}
	req.Header.Set("User-Agent", UserAgent)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return &UserInfo{IsAvailable: false}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &UserInfo{IsAvailable: false}, err
	}

	rawBytes, err := ExtractJSONP(string(body))
	if err != nil {
		return &UserInfo{IsAvailable: false}, err
	}

	var rawMap map[string]any
	if err := json.Unmarshal(rawBytes, &rawMap); err != nil {
		return &UserInfo{IsAvailable: false}, err
	}

	info := &UserInfo{
		IsAvailable: true,
		RawData:     rawMap,
	}

	if clientIP, ok := rawMap["client_ip"].(string); ok {
		info.ClientIP = clientIP
	}
	if onlineIP, ok := rawMap["online_ip"].(string); ok {
		info.OnlineIP = onlineIP
	}
	if username, ok := rawMap["user_name"].(string); ok {
		info.UserName = username
	}
	if mac, ok := rawMap["user_mac"].(string); ok {
		info.UserMac = mac
	}

	// Parse balance
	if balanceVal, ok := rawMap["user_balance"]; ok {
		switch v := balanceVal.(type) {
		case float64:
			info.UserBalance = v
		case string:
			f, _ := strconv.ParseFloat(v, 64)
			info.UserBalance = f
		}
	}

	// Parse traffic
	parseInt64 := func(key string) int64 {
		if val, ok := rawMap[key]; ok {
			switch v := val.(type) {
			case float64:
				return int64(v)
			case string:
				n, _ := strconv.ParseInt(v, 10, 64)
				return n
			}
		}
		return 0
	}

	info.UsedBytes = parseInt64("sum_bytes")
	info.AllBytes = parseInt64("all_bytes")
	info.BytesIn = parseInt64("sum_bytes_in")
	info.BytesOut = parseInt64("sum_bytes_out")
	info.KeepaliveTime = parseInt64("keepalive_time")
	info.OnlineTime = parseInt64("user_time")

	if errMsg, ok := rawMap["error_msg"].(string); ok {
		info.ErrorMsg = errMsg
	}
	if errCode, ok := rawMap["error"].(string); ok {
		info.Error = errCode
	}

	// Check online state: if user_name or online_ip is present and error is "ok" or not "not_online_error"
	if (info.UserName != "" || info.OnlineIP != "") && !strings.Contains(info.Error, "not_online") {
		info.IsOnline = true
	}

	return info, nil
}

// AutoDiscoverACID queries HTTP redirect headers or portal default page to find ac_id.
func AutoDiscoverACID(ctx context.Context, host string) (string, error) {
	client := &http.Client{
		Timeout: 4 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	targetURL := fmt.Sprintf("http://%s/", host)
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return "1", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "1", err
	}
	defer resp.Body.Close()

	location := resp.Header.Get("Location")
	if location != "" {
		u, err := url.Parse(location)
		if err == nil {
			acid := u.Query().Get("ac_id")
			if acid != "" {
				return acid, nil
			}
		}
	}

	return "1", nil
}
