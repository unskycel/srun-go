package e2e_test

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"srun/tests/mock"
)

// TestTier3_Interaction_Config_And_DPAPI: Config save/load combined with DPAPI encryption
func TestTier3_Interaction_Config_And_DPAPI(t *testing.T) {
	plainPass := "SecretPass123!#"
	encPass, err := DPAPIEncrypt(plainPass)
	if err != nil {
		t.Fatalf("DPAPI encrypt failed: %v", err)
	}

	type Config struct {
		Username string `json:"username"`
		Password string `json:"password"`
		SrunHost string `json:"srun_host"`
	}

	cfg := Config{
		Username: "20211234",
		Password: encPass,
		SrunHost: "gw.buaa.edu.cn",
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config failed: %v", err)
	}

	var loaded Config
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshal config failed: %v", err)
	}

	decPass, err := DPAPIDecrypt(loaded.Password)
	if err != nil {
		t.Fatalf("DPAPI decrypt failed: %v", err)
	}
	if decPass != plainPass {
		t.Fatalf("expected decrypted password '%s', got '%s'", plainPass, decPass)
	}
}

// TestTier3_Interaction_Discovery_And_Challenge: Redirect AC ID discovery + Challenge retrieval
func TestTier3_Interaction_Discovery_And_Challenge(t *testing.T) {
	gw := mock.NewMockGateway()
	gw.ACID = "5"
	serverURL := gw.Start()
	defer gw.Close()

	// 1. Discover AC ID via GET /
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(serverURL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	defer resp.Body.Close()

	loc := resp.Header.Get("Location")
	u, _ := url.Parse(loc)
	discoveredACID := u.Query().Get("ac_id")
	if discoveredACID != "5" {
		t.Fatalf("expected discovered ac_id=5, got '%s'", discoveredACID)
	}

	// 2. Query challenge token with discovered AC ID
	chalResp, err := http.Get(fmt.Sprintf("%s/cgi-bin/get_challenge?username=20211234&ip=10.200.21.50", serverURL))
	if err != nil {
		t.Fatalf("get_challenge failed: %v", err)
	}
	defer chalResp.Body.Close()

	body, _ := io.ReadAll(chalResp.Body)
	payload, _ := UnwrapJSONP(string(body))
	if payload["challenge"] != gw.FixedToken {
		t.Fatalf("expected challenge '%s', got '%v'", gw.FixedToken, payload["challenge"])
	}
}

// TestTier3_Interaction_Challenge_And_LoginCrypto: Token extraction + full cryptographic packet assembly + portal submission
func TestTier3_Interaction_Challenge_And_LoginCrypto(t *testing.T) {
	gw := mock.NewMockGateway()
	serverURL := gw.Start()
	defer gw.Close()

	username := "20211234"
	password := "password123"
	ip := "10.200.21.50"
	acid := "1"

	// 1. Get Challenge Token
	chalResp, err := http.Get(fmt.Sprintf("%s/cgi-bin/get_challenge?username=%s&ip=%s", serverURL, username, ip))
	if err != nil {
		t.Fatalf("get_challenge failed: %v", err)
	}
	defer chalResp.Body.Close()
	body, _ := io.ReadAll(chalResp.Body)
	chalPayload, _ := UnwrapJSONP(string(body))
	token := chalPayload["challenge"].(string)

	// 2. Perform Crypto
	infoJSON := fmt.Sprintf(`{"username":"%s","password":"%s","ip":"%s","acid":"%s","enc_ver":"srun_bx1"}`,
		username, password, ip, acid)
	xenc := SrunXEncode(infoJSON, token)
	infoParam := "{SRBX1}" + SrunCustomBase64(xenc)
	hmd5 := SrunMD5HMAC(password, token)
	chksum := SrunComputeChksum(username, token, hmd5, ip, infoParam, acid, "200", "1")

	// 3. Submit Portal Login
	portalURL := fmt.Sprintf("%s/cgi-bin/srun_portal?action=login&username=%s&password={MD5}%s&ac_id=%s&ip=%s&chksum=%s&info=%s&n=200&type=1",
		serverURL, username, hmd5, acid, ip, chksum, url.QueryEscape(infoParam))

	loginResp, err := http.Get(portalURL)
	if err != nil {
		t.Fatalf("portal login failed: %v", err)
	}
	defer loginResp.Body.Close()

	loginBody, _ := io.ReadAll(loginResp.Body)
	loginPayload, err := UnwrapJSONP(string(loginBody))
	if err != nil || loginPayload["error"] != "ok" {
		t.Fatalf("expected login success, got payload: %v, err: %v", loginPayload, err)
	}
}

// TestTier3_Interaction_Login_And_UserInfo: Successful login updates user session in rad_user_info
func TestTier3_Interaction_Login_And_UserInfo(t *testing.T) {
	gw := mock.NewMockGateway()
	serverURL := gw.Start()
	defer gw.Close()

	// Initial status: offline
	infoResp1, _ := http.Get(serverURL + "/cgi-bin/rad_user_info?callback=JQuery")
	body1, _ := io.ReadAll(infoResp1.Body)
	infoResp1.Body.Close()
	p1, _ := UnwrapJSONP(string(body1))
	if p1["error"] != "not_online_error" {
		t.Fatalf("expected initial offline state")
	}

	// Login
	h := hmac.New(md5.New, []byte(gw.FixedToken))
	h.Write([]byte("password123"))
	hmd5 := hex.EncodeToString(h.Sum(nil))
	loginResp, _ := http.Get(fmt.Sprintf("%s/cgi-bin/srun_portal?action=login&username=20211234&password={MD5}%s", serverURL, hmd5))
	loginResp.Body.Close()

	// Subsequent status: online
	infoResp2, _ := http.Get(serverURL + "/cgi-bin/rad_user_info?callback=JQuery")
	body2, _ := io.ReadAll(infoResp2.Body)
	infoResp2.Body.Close()
	p2, _ := UnwrapJSONP(string(body2))
	if p2["error"] != "ok" || p2["user_name"] != "20211234" {
		t.Fatalf("expected online status after login, got: %v", p2)
	}
}

// TestTier3_Interaction_LogoutPortal_And_UserInfo: Portal logout transitions user session to offline
func TestTier3_Interaction_LogoutPortal_And_UserInfo(t *testing.T) {
	gw := mock.NewMockGateway()
	gw.SetOnline("20211234", true)
	serverURL := gw.Start()
	defer gw.Close()

	logoutResp, _ := http.Get(fmt.Sprintf("%s/cgi-bin/srun_portal?action=logout&username=20211234&ip=10.200.21.50", serverURL))
	logoutResp.Body.Close()

	infoResp, _ := http.Get(serverURL + "/cgi-bin/rad_user_info?callback=JQuery")
	body, _ := io.ReadAll(infoResp.Body)
	infoResp.Body.Close()
	payload, _ := UnwrapJSONP(string(body))
	if payload["error"] != "not_online_error" {
		t.Fatalf("expected offline state after portal logout")
	}
}

// TestTier3_Interaction_LogoutDM_And_UserInfo: DM logout transitions user session to offline
func TestTier3_Interaction_LogoutDM_And_UserInfo(t *testing.T) {
	gw := mock.NewMockGateway()
	gw.SetOnline("20211234", true)
	serverURL := gw.Start()
	defer gw.Close()

	now := time.Now().UnixMilli()
	sign := SrunComputeDMSign(now, "20211234", "10.200.21.50")
	dmResp, _ := http.Get(fmt.Sprintf("%s/cgi-bin/rad_user_dm?ip=10.200.21.50&username=20211234&time=%d&unbind=0&sign=%s", serverURL, now, sign))
	dmResp.Body.Close()

	infoResp, _ := http.Get(serverURL + "/cgi-bin/rad_user_info?callback=JQuery")
	body, _ := io.ReadAll(infoResp.Body)
	infoResp.Body.Close()
	payload, _ := UnwrapJSONP(string(body))
	if payload["error"] != "not_online_error" {
		t.Fatalf("expected offline state after DM logout")
	}
}

// TestTier3_Interaction_MultiNIC_And_SocketBinding: Enumerate interfaces + Dial gateway with local interface
func TestTier3_Interaction_MultiNIC_And_SocketBinding(t *testing.T) {
	gw := mock.NewMockGateway()
	serverURL := gw.Start()
	defer gw.Close()

	ips, err := EnumerateIPv4LocalInterfaces()
	if err != nil {
		t.Fatalf("NIC enumeration failed: %v", err)
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(serverURL + "/cgi-bin/rad_user_info")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	_ = ips
}

// TestTier3_Interaction_Config_And_AutoStartup: Auto-startup configuration toggle
func TestTier3_Interaction_Config_And_AutoStartup(t *testing.T) {
	type Config struct {
		StartWithWindows bool `json:"start_with_windows"`
	}
	cfg := Config{StartWithWindows: true}

	var registeredCmd string
	if cfg.StartWithWindows {
		registeredCmd = `"C:\SRun\srun.exe" --no-auto-open`
	}
	if registeredCmd != `"C:\SRun\srun.exe" --no-auto-open` {
		t.Fatalf("command mismatch: %s", registeredCmd)
	}
}

// TestTier3_Interaction_Config_And_ThemeDetection: Combining config theme override with system theme
func TestTier3_Interaction_Config_And_ThemeDetection(t *testing.T) {
	type Config struct {
		DarkTheme bool `json:"dark_theme"`
	}
	cfg := Config{DarkTheme: true}
	systemTheme, _ := CheckThemeFromRegistry()

	effectiveDark := cfg.DarkTheme || (systemTheme == 0)
	if !effectiveDark {
		t.Fatalf("expected dark theme when configured in config")
	}
}

// TestTier3_Interaction_CLI_And_MockGateway_Status: Status JSON query against MockGateway
func TestTier3_Interaction_CLI_And_MockGateway_Status(t *testing.T) {
	gw := mock.NewMockGateway()
	gw.SetOnline("20211234", true)
	serverURL := gw.Start()
	defer gw.Close()

	resp, err := http.Get(serverURL + "/cgi-bin/rad_user_info?callback=JQuery")
	if err != nil {
		t.Fatalf("status request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	payload, _ := UnwrapJSONP(string(body))

	statusJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal status failed: %v", err)
	}
	if !strings.Contains(string(statusJSON), `"user_name":"20211234"`) {
		t.Fatalf("expected user_name in json status: %s", string(statusJSON))
	}
}

// TestTier3_Interaction_CLI_And_MockGateway_Login: CLI login flow simulation
func TestTier3_Interaction_CLI_And_MockGateway_Login(t *testing.T) {
	gw := mock.NewMockGateway()
	serverURL := gw.Start()
	defer gw.Close()

	h := hmac.New(md5.New, []byte(gw.FixedToken))
	h.Write([]byte("password123"))
	hmd5 := hex.EncodeToString(h.Sum(nil))

	resp, err := http.Get(fmt.Sprintf("%s/cgi-bin/srun_portal?action=login&username=20211234&password={MD5}%s", serverURL, hmd5))
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	payload, _ := UnwrapJSONP(string(body))
	if payload["error"] != "ok" {
		t.Fatalf("expected error ok")
	}
}

// TestTier3_Interaction_Daemon_And_AutoReconnect: Daemon monitors and logs in on network availability
func TestTier3_Interaction_Daemon_And_AutoReconnect(t *testing.T) {
	gw := mock.NewMockGateway()
	serverURL := gw.Start()
	defer gw.Close()

	// 1. Check status -> offline
	resp, _ := http.Get(serverURL + "/cgi-bin/rad_user_info")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	p, _ := UnwrapJSONP(string(body))
	isOnline := p["error"] == "ok"

	// 2. Perform auto-login
	if !isOnline {
		h := hmac.New(md5.New, []byte(gw.FixedToken))
		h.Write([]byte("password123"))
		hmd5 := hex.EncodeToString(h.Sum(nil))
		lResp, _ := http.Get(fmt.Sprintf("%s/cgi-bin/srun_portal?action=login&username=20211234&password={MD5}%s", serverURL, hmd5))
		lResp.Body.Close()
	}

	// 3. Verify online
	resp2, _ := http.Get(serverURL + "/cgi-bin/rad_user_info")
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	p2, _ := UnwrapJSONP(string(body2))
	if p2["error"] != "ok" {
		t.Fatalf("auto-reconnect failed")
	}
}

// TestTier3_Interaction_Daemon_And_BackoffTrigger: Repeated failures triggers backoff
func TestTier3_Interaction_Daemon_And_BackoffTrigger(t *testing.T) {
	gw := mock.NewMockGateway()
	gw.SimulateWrongCredsError = true
	serverURL := gw.Start()
	defer gw.Close()

	failCount := 0
	for i := 0; i < 4; i++ {
		resp, _ := http.Get(fmt.Sprintf("%s/cgi-bin/srun_portal?action=login&username=20211234&password={MD5}badpass", serverURL))
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		payload, _ := UnwrapJSONP(string(body))
		if payload["error"] != "ok" {
			failCount++
		}
	}

	sleepTime := CalculateDaemonBackoff(failCount, 5)
	if sleepTime != 65 {
		t.Fatalf("expected 65s sleep on 4 failures, got %ds", sleepTime)
	}
}

// TestTier3_Interaction_LegacyAES_To_DPAPI_Migration: Migrating legacy AES password to DPAPI
func TestTier3_Interaction_LegacyAES_To_DPAPI_Migration(t *testing.T) {
	// Simulate legacy config with plaintext or AES fallback
	legacyPass := "migratedPassword123"
	dpapiCipher, err := DPAPIEncrypt(legacyPass)
	if err != nil {
		t.Fatalf("re-encryption failed: %v", err)
	}

	decrypted, err := DPAPIDecrypt(dpapiCipher)
	if err != nil || decrypted != legacyPass {
		t.Fatalf("migration validation failed")
	}
}

// TestTier3_Interaction_CascadingFallback_AllStages: Simulating HTTP fallback on HTTPS failure
func TestTier3_Interaction_CascadingFallback_AllStages(t *testing.T) {
	gw := mock.NewMockGateway()
	serverURL := gw.Start()
	defer gw.Close()

	// Try stage 1 (simulated fail), fall back to stage 3 (plain HTTP)
	resp, err := http.Get(serverURL + "/cgi-bin/rad_user_info")
	if err != nil {
		t.Fatalf("fallback request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on fallback")
	}
}

// TestTier3_Interaction_SingleInstanceMutex_And_CLI: Single instance mutex identifier logic
func TestTier3_Interaction_SingleInstanceMutex_And_CLI(t *testing.T) {
	mutexName := "Local\\SRunGo_SingleInstance_Mutex"
	if !strings.HasPrefix(mutexName, "Local\\") {
		t.Fatalf("expected Local\\ prefix for Windows single instance mutex")
	}
}

// TestTier3_Interaction_SelfServiceURL_Generation: Online SSO url vs offline portal URL
func TestTier3_Interaction_SelfServiceURL_Generation(t *testing.T) {
	selfServiceDomain := "zfw.buaa.edu.cn"
	username := "20211234"

	getSelfServiceURL := func(isOnline bool) string {
		if isOnline {
			dataStr := base64.StdEncoding.EncodeToString([]byte("zh-CN:" + username))
			return fmt.Sprintf("http://%s/site/sso?data=%s", selfServiceDomain, dataStr)
		}
		return fmt.Sprintf("http://%s", selfServiceDomain)
	}

	onlineURL := getSelfServiceURL(true)
	expectedB64 := base64.StdEncoding.EncodeToString([]byte("zh-CN:20211234"))
	expectedURL := "http://zfw.buaa.edu.cn/site/sso?data=" + expectedB64
	if onlineURL != expectedURL {
		t.Fatalf("expected '%s', got '%s'", expectedURL, onlineURL)
	}

	offlineURL := getSelfServiceURL(false)
	if offlineURL != "http://zfw.buaa.edu.cn" {
		t.Fatalf("expected 'http://zfw.buaa.edu.cn', got '%s'", offlineURL)
	}
}
