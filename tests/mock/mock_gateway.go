package mock

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// UserSession represents the online/offline state of a user and IP
type UserSession struct {
	Username      string  `json:"user_name"`
	Password      string  `json:"password"`
	IP            string  `json:"client_ip"`
	MAC           string  `json:"user_mac"`
	Balance       float64 `json:"user_balance"`
	AllBytes      int64   `json:"all_bytes"`
	BytesIn       int64   `json:"bytes_in"`
	BytesOut      int64   `json:"bytes_out"`
	KeepaliveTime int64   `json:"keepalive_time"`
	OnlineTime    int64   `json:"online_time"`
	IsOnline      bool    `json:"is_online"`
	LoginCount    int     `json:"login_count"`
	MaxLogins     int     `json:"max_logins"`
	IsArrears     bool    `json:"is_arrears"`
	IsDisabled    bool    `json:"is_disabled"`
	IsLocked      bool    `json:"is_locked"`
	RetryCount    int     `json:"retry_count"`
}

// RequestRecord captures details of an HTTP request received by MockGateway
type RequestRecord struct {
	Method    string
	Path      string
	Query     url.Values
	Headers   http.Header
	Timestamp time.Time
}

// MockGateway simulates the Srun campus network authentication gateway
type MockGateway struct {
	mu           sync.Mutex
	Server       *httptest.Server
	BaseURL      string
	Host         string
	Port         string
	ACID         string
	DefaultIP    string
	FixedToken   string
	Users        map[string]*UserSession // keyed by username
	SessionsByIP map[string]*UserSession // keyed by client_ip
	Requests     []RequestRecord

	// Failure simulation flags
	SimulateRedirectFail    bool
	SimulateChallengeFail   bool
	SimulateMalformedJSONP  bool
	SimulatePortalFail      bool
	SimulateDMOnlyLogout    bool
	SimulateNetworkTimeout  bool
	SimulateServerError     bool
	SimulateWrongCredsError bool
	SimulateLockoutError    bool
	SimulateArrearsError    bool
	SimulateDeviceLimit     bool

	CustomPortalResp string
	CustomInfoResp   string
}

// NewMockGateway creates a configured mock Srun gateway instance
func NewMockGateway() *MockGateway {
	gw := &MockGateway{
		ACID:         "1",
		DefaultIP:    "10.200.21.50",
		FixedToken:   "bb983c27e4e1a0b345f7823901acde45",
		Users:        make(map[string]*UserSession),
		SessionsByIP: make(map[string]*UserSession),
		Requests:     make([]RequestRecord, 0),
	}

	// Register default test user
	gw.SetUser(&UserSession{
		Username:      "20211234",
		Password:      "password123",
		IP:            "10.200.21.50",
		MAC:           "50:eb:f6:12:34:56",
		Balance:       25.50,
		AllBytes:      104857600,
		BytesIn:       83886080,
		BytesOut:      20971520,
		KeepaliveTime: 3600,
		OnlineTime:    time.Now().Unix() - 3600,
		IsOnline:      false,
		MaxLogins:     3,
	})

	return gw
}

// Start launches the httptest server and configures BaseURL and Host
func (gw *MockGateway) Start() string {
	mux := http.NewServeMux()
	mux.HandleFunc("/", gw.handleRoot)
	mux.HandleFunc("/cgi-bin/rad_user_info", gw.handleRadUserInfo)
	mux.HandleFunc("/cgi-bin/get_challenge", gw.handleGetChallenge)
	mux.HandleFunc("/cgi-bin/srun_portal", gw.handleSrunPortal)
	mux.HandleFunc("/cgi-bin/rad_user_dm", gw.handleRadUserDM)
	mux.HandleFunc("/srun_portal_pc", gw.handlePortalPC)

	gw.Server = httptest.NewServer(mux)
	gw.BaseURL = gw.Server.URL

	u, _ := url.Parse(gw.BaseURL)
	gw.Host = u.Host
	gw.Port = u.Port()

	return gw.BaseURL
}

// Close terminates the mock server
func (gw *MockGateway) Close() {
	if gw.Server != nil {
		gw.Server.Close()
	}
}

// SetUser configures a user profile in the mock gateway
func (gw *MockGateway) SetUser(user *UserSession) {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	gw.Users[user.Username] = user
	if user.IP != "" {
		gw.SessionsByIP[user.IP] = user
	}
}

// SetOnline sets the online status for a specific user or IP
func (gw *MockGateway) SetOnline(usernameOrIP string, online bool) {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	if user, ok := gw.Users[usernameOrIP]; ok {
		user.IsOnline = online
		if online {
			user.OnlineTime = time.Now().Unix()
		}
	}
	if user, ok := gw.SessionsByIP[usernameOrIP]; ok {
		user.IsOnline = online
		if online {
			user.OnlineTime = time.Now().Unix()
		}
	}
}

// RecordRequest logs an incoming HTTP request
func (gw *MockGateway) recordRequest(r *http.Request) {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	gw.Requests = append(gw.Requests, RequestRecord{
		Method:    r.Method,
		Path:      r.URL.Path,
		Query:     r.URL.Query(),
		Headers:   r.Header.Clone(),
		Timestamp: time.Now(),
	})
}

// GetRequests returns a copy of recorded requests
func (gw *MockGateway) GetRequests() []RequestRecord {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	copied := make([]RequestRecord, len(gw.Requests))
	copy(copied, gw.Requests)
	return copied
}

// GetRequestCount returns the count of requests matching a specific path
func (gw *MockGateway) GetRequestCount(path string) int {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	count := 0
	for _, req := range gw.Requests {
		if req.Path == path {
			count++
		}
	}
	return count
}

// ResetRequests clears recorded requests
func (gw *MockGateway) ResetRequests() {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	gw.Requests = make([]RequestRecord, 0)
}

func wrapJSONP(callback string, data any) string {
	b, _ := json.Marshal(data)
	if callback != "" {
		return fmt.Sprintf("%s(%s)", callback, string(b))
	}
	return string(b)
}

// Root handler: simulates Captive Portal redirect discovery on GET /
func (gw *MockGateway) handleRoot(w http.ResponseWriter, r *http.Request) {
	gw.recordRequest(r)
	gw.mu.Lock()
	defer gw.mu.Unlock()

	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	if gw.SimulateServerError {
		http.Error(w, "Internal Gateway Error", http.StatusInternalServerError)
		return
	}

	if gw.SimulateRedirectFail {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Portal Root without redirect</body></html>"))
		return
	}

	// 302 Redirect to portal page with ac_id
	target := fmt.Sprintf("/srun_portal_pc?ac_id=%s&theme=basic", gw.ACID)
	http.Redirect(w, r, target, http.StatusFound)
}

func (gw *MockGateway) handlePortalPC(w http.ResponseWriter, r *http.Request) {
	gw.recordRequest(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("<html><body>Welcome to Srun Portal</body></html>"))
}

// Handler for /cgi-bin/rad_user_info
func (gw *MockGateway) handleRadUserInfo(w http.ResponseWriter, r *http.Request) {
	gw.recordRequest(r)
	gw.mu.Lock()
	defer gw.mu.Unlock()

	if gw.SimulateServerError {
		http.Error(w, "500 Server Error", http.StatusInternalServerError)
		return
	}

	if gw.CustomInfoResp != "" {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Write([]byte(gw.CustomInfoResp))
		return
	}

	if gw.SimulateMalformedJSONP {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Write([]byte("Invalid_Callback({malformed json"))
		return
	}

	callback := r.URL.Query().Get("callback")
	if callback == "" {
		callback = "JQuery"
	}

	// Lookup user session by IP or default
	clientIP := gw.DefaultIP
	var session *UserSession
	for _, s := range gw.SessionsByIP {
		session = s
		break
	}
	if session == nil {
		for _, s := range gw.Users {
			session = s
			break
		}
	}

	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")

	if session != nil && session.IsOnline {
		resp := map[string]any{
			"client_ip":      session.IP,
			"online_ip":      session.IP,
			"user_name":      session.Username,
			"user_mac":       session.MAC,
			"user_balance":   session.Balance,
			"all_bytes":      session.AllBytes,
			"bytes_in":       session.BytesIn,
			"bytes_out":      session.BytesOut,
			"keepalive_time": session.KeepaliveTime,
			"online_time":    session.OnlineTime,
			"error":          "ok",
		}
		w.Write([]byte(wrapJSONP(callback, resp)))
	} else {
		resp := map[string]any{
			"error":     "not_online_error",
			"client_ip": clientIP,
		}
		w.Write([]byte(wrapJSONP(callback, resp)))
	}
}

// Handler for /cgi-bin/get_challenge
func (gw *MockGateway) handleGetChallenge(w http.ResponseWriter, r *http.Request) {
	gw.recordRequest(r)
	gw.mu.Lock()
	defer gw.mu.Unlock()

	if gw.SimulateServerError {
		http.Error(w, "500 Internal Error", http.StatusInternalServerError)
		return
	}

	if gw.SimulateChallengeFail {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Write([]byte("callback({\"error\":\"challenge_failed\",\"ecode\":1})"))
		return
	}

	if gw.SimulateMalformedJSONP {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Write([]byte("callback({corrupted"))
		return
	}

	q := r.URL.Query()
	callback := q.Get("callback")
	if callback == "" {
		callback = "jQuery112404953340710317169_" + strconv.FormatInt(time.Now().UnixMilli(), 10)
	}
	ip := q.Get("ip")
	if ip == "" {
		ip = gw.DefaultIP
	}

	resp := map[string]any{
		"challenge": gw.FixedToken,
		"client_ip": ip,
		"ecode":     0,
		"error":     "ok",
		"error_msg": "",
		"expire":    "180",
		"online_ip": ip,
		"res":       "ok",
	}

	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Write([]byte(wrapJSONP(callback, resp)))
}

// Handler for /cgi-bin/srun_portal (login, logout)
func (gw *MockGateway) handleSrunPortal(w http.ResponseWriter, r *http.Request) {
	gw.recordRequest(r)
	gw.mu.Lock()
	defer gw.mu.Unlock()

	if gw.SimulateServerError {
		http.Error(w, "500 Server Error", http.StatusInternalServerError)
		return
	}

	if gw.CustomPortalResp != "" {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Write([]byte(gw.CustomPortalResp))
		return
	}

	q := r.URL.Query()
	action := q.Get("action")
	callback := q.Get("callback")
	username := q.Get("username")
	ip := q.Get("ip")
	if ip == "" {
		ip = gw.DefaultIP
	}

	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")

	if action == "login" {
		if gw.SimulatePortalFail {
			resp := map[string]any{"ecode": 1, "error": "portal_auth_error", "error_msg": "Portal Authentication Error"}
			w.Write([]byte(wrapJSONP(callback, resp)))
			return
		}

		if gw.SimulateLockoutError {
			resp := map[string]any{"ecode": 1, "error": "E2553: 密码重试次数过多，已被锁定", "error_msg": "E2553: 密码重试次数过多，已被锁定"}
			w.Write([]byte(wrapJSONP(callback, resp)))
			return
		}

		if gw.SimulateArrearsError {
			resp := map[string]any{"ecode": 1, "error": "E2532: 账号已欠费", "error_msg": "E2532: 账号已欠费"}
			w.Write([]byte(wrapJSONP(callback, resp)))
			return
		}

		if gw.SimulateDeviceLimit {
			resp := map[string]any{"ecode": 1, "error": "E2534: 登录次数超限", "error_msg": "E2534: 登录次数超限"}
			w.Write([]byte(wrapJSONP(callback, resp)))
			return
		}

		user, exists := gw.Users[username]
		if !exists {
			resp := map[string]any{"ecode": 1, "error": "E2606: 用户不存在", "error_msg": "E2606: 用户不存在"}
			w.Write([]byte(wrapJSONP(callback, resp)))
			return
		}

		if user.IsLocked {
			resp := map[string]any{"ecode": 1, "error": "E2553: 密码重试次数过多，已被锁定", "error_msg": "E2553: 密码重试次数过多，已被锁定"}
			w.Write([]byte(wrapJSONP(callback, resp)))
			return
		}

		if user.IsArrears {
			resp := map[string]any{"ecode": 1, "error": "E2532: 账号已欠费", "error_msg": "E2532: 账号已欠费"}
			w.Write([]byte(wrapJSONP(callback, resp)))
			return
		}

		// Verify password hash
		providedPass := q.Get("password")
		h := hmac.New(md5.New, []byte(gw.FixedToken))
		h.Write([]byte(user.Password))
		expectedHMD5 := hex.EncodeToString(h.Sum(nil))
		expectedPass := "{MD5}" + expectedHMD5

		if gw.SimulateWrongCredsError || (providedPass != expectedPass && !strings.Contains(providedPass, user.Password)) {
			user.RetryCount++
			if user.RetryCount >= 3 {
				user.IsLocked = true
			}
			resp := map[string]any{"ecode": 1, "error": "E2531: 用户名或密码错误", "error_msg": "E2531: 用户名或密码错误"}
			w.Write([]byte(wrapJSONP(callback, resp)))
			return
		}

		// Login Successful
		user.IsOnline = true
		user.IP = ip
		user.RetryCount = 0
		user.OnlineTime = time.Now().Unix()
		gw.SessionsByIP[ip] = user

		resp := map[string]any{
			"ecode":      0,
			"error":      "ok",
			"error_msg":  "",
			"res":        "ok",
			"client_ip":  ip,
			"online_ip":  ip,
			"user_name":  username,
		}
		w.Write([]byte(wrapJSONP(callback, resp)))
		return
	}

	if action == "logout" {
		if gw.SimulateDMOnlyLogout {
			// Fail portal logout, forcing client to fallback to rad_user_dm
			resp := map[string]any{"ecode": 1, "error": "portal_logout_fail", "error_msg": "portal logout failed"}
			w.Write([]byte(wrapJSONP(callback, resp)))
			return
		}

		if user, ok := gw.Users[username]; ok {
			user.IsOnline = false
		}
		if user, ok := gw.SessionsByIP[ip]; ok {
			user.IsOnline = false
		}

		resp := map[string]any{
			"ecode":     0,
			"error":     "ok",
			"error_msg": "",
			"res":       "ok",
		}
		w.Write([]byte(wrapJSONP(callback, resp)))
		return
	}

	// Unknown action
	resp := map[string]any{"ecode": 1, "error": "unknown_action"}
	w.Write([]byte(wrapJSONP(callback, resp)))
}

// Handler for /cgi-bin/rad_user_dm (Classic DM logout fallback)
func (gw *MockGateway) handleRadUserDM(w http.ResponseWriter, r *http.Request) {
	gw.recordRequest(r)
	gw.mu.Lock()
	defer gw.mu.Unlock()

	if gw.SimulateServerError {
		http.Error(w, "500 Server Error", http.StatusInternalServerError)
		return
	}

	q := r.URL.Query()
	ip := q.Get("ip")
	username := q.Get("username")
	tStr := q.Get("time")
	sign := q.Get("sign")

	if ip == "" || username == "" || tStr == "" || sign == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing_parameters"))
		return
	}

	// Verify SHA1 sign: SHA1(t + username + ip + "0" + t)
	expectedSignStr := tStr + username + ip + "0" + tStr
	s := sha1.Sum([]byte(expectedSignStr))
	expectedSign := hex.EncodeToString(s[:])

	if !strings.EqualFold(sign, expectedSign) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("invalid_sign"))
		return
	}

	// Mark session offline
	if user, ok := gw.Users[username]; ok {
		user.IsOnline = false
	}
	if user, ok := gw.SessionsByIP[ip]; ok {
		user.IsOnline = false
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("logout_ok"))
}
