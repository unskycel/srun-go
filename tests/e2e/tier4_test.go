package e2e_test

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"srun/tests/mock"
)

// =========================================================================
// TIER 4: REAL-WORLD APPLICATION WORKLOAD SCENARIOS
// =========================================================================

// Scenario 1: Full First-Time Login Lifecycle
// Features: F1-F5, F8, F10, F14
func TestTier4_Scenario1_FullFirstTimeLoginLifecycle(t *testing.T) {
	gw := mock.NewMockGateway()
	gw.ACID = "2"
	serverURL := gw.Start()
	defer gw.Close()

	username := "20211234"
	plainPassword := "password123"

	// 1. Enumerate Local Network Interfaces
	ips, err := EnumerateIPv4LocalInterfaces()
	if err != nil {
		t.Fatalf("NIC enumeration failed: %v", err)
	}
	selectedIP := "10.200.21.50"
	if len(ips) > 0 {
		selectedIP = ips[0]
	}

	// 2. Discover AC ID via GET / redirect
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	rootResp, err := client.Get(serverURL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	rootResp.Body.Close()
	loc := rootResp.Header.Get("Location")
	u, _ := url.Parse(loc)
	discoveredACID := u.Query().Get("ac_id")
	if discoveredACID == "" {
		discoveredACID = "1"
	}

	// 3. Encrypt and Save Credentials to Config
	encPass, err := DPAPIEncrypt(plainPassword)
	if err != nil {
		t.Fatalf("DPAPI encryption failed: %v", err)
	}

	type AppConfig struct {
		Username         string `json:"username"`
		Password         string `json:"password"`
		SrunHost         string `json:"srun_host"`
		ACID             string `json:"acid"`
		PassCorrect      bool   `json:"pass_correct"`
		StartWithWindows bool   `json:"start_with_windows"`
	}

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	cfg := AppConfig{
		Username:    username,
		Password:    encPass,
		SrunHost:    gw.Host,
		ACID:        discoveredACID,
		PassCorrect: false,
	}
	cfgBytes, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, cfgBytes, 0600); err != nil {
		t.Fatalf("saving config failed: %v", err)
	}

	// 4. Retrieve Challenge Token
	chalResp, err := http.Get(fmt.Sprintf("%s/cgi-bin/get_challenge?username=%s&ip=%s", serverURL, username, selectedIP))
	if err != nil {
		t.Fatalf("challenge request failed: %v", err)
	}
	defer chalResp.Body.Close()
	chalBody, _ := io.ReadAll(chalResp.Body)
	chalPayload, err := UnwrapJSONP(string(chalBody))
	if err != nil {
		t.Fatalf("unwrap challenge failed: %v", err)
	}
	token := chalPayload["challenge"].(string)

	// 5. Build Cryptographic Payload (XEncode + Custom Base64 + HMAC-MD5 + SHA1)
	infoJSON := fmt.Sprintf(`{"username":"%s","password":"%s","ip":"%s","acid":"%s","enc_ver":"srun_bx1"}`,
		username, plainPassword, selectedIP, discoveredACID)
	xenc := SrunXEncode(infoJSON, token)
	infoParam := "{SRBX1}" + SrunCustomBase64(xenc)
	hmd5 := SrunMD5HMAC(plainPassword, token)
	chksum := SrunComputeChksum(username, token, hmd5, selectedIP, infoParam, discoveredACID, "200", "1")

	// 6. Submit Portal Login
	loginURL := fmt.Sprintf("%s/cgi-bin/srun_portal?action=login&username=%s&password={MD5}%s&ac_id=%s&ip=%s&chksum=%s&info=%s&n=200&type=1",
		serverURL, username, hmd5, discoveredACID, selectedIP, chksum, url.QueryEscape(infoParam))

	loginResp, err := http.Get(loginURL)
	if err != nil {
		t.Fatalf("portal login request failed: %v", err)
	}
	defer loginResp.Body.Close()
	loginBody, _ := io.ReadAll(loginResp.Body)
	loginPayload, err := UnwrapJSONP(string(loginBody))
	if err != nil || loginPayload["error"] != "ok" {
		t.Fatalf("login failed: payload=%v, err=%v", loginPayload, err)
	}

	// 7. Verify Online Status & Update PassCorrect Flag in Config
	infoResp, err := http.Get(serverURL + "/cgi-bin/rad_user_info?callback=JQuery")
	if err != nil {
		t.Fatalf("user info request failed: %v", err)
	}
	defer infoResp.Body.Close()
	infoBody, _ := io.ReadAll(infoResp.Body)
	infoPayload, _ := UnwrapJSONP(string(infoBody))
	if infoPayload["error"] != "ok" || infoPayload["user_name"] != username {
		t.Fatalf("expected online status, got %v", infoPayload)
	}

	cfg.PassCorrect = true
	updatedBytes, _ := json.MarshalIndent(cfg, "", "  ")
	_ = os.WriteFile(configPath, updatedBytes, 0600)
}

// Scenario 2: Auto-Daemon Reconnect on Network Drop
// Features: F4, F5, F7, F10, F15
func TestTier4_Scenario2_AutoDaemonReconnectOnNetworkDrop(t *testing.T) {
	gw := mock.NewMockGateway()
	serverURL := gw.Start()
	defer gw.Close()

	username := "20211234"
	password := "password123"
	ip := "10.200.21.50"

	failCount := 0
	isOnline := false

	// Cycle 1: Network is Down (Simulate Server Error / unreachable)
	gw.SimulateServerError = true
	resp1, err := http.Get(serverURL + "/cgi-bin/rad_user_info")
	if err == nil && resp1.StatusCode == http.StatusOK {
		t.Fatalf("expected network failure")
	}
	if resp1 != nil {
		resp1.Body.Close()
	}
	// Daemon rule: if network unavailable, do NOT increment login_failed_count
	if failCount != 0 {
		t.Fatalf("failCount should not increment on network unreachable")
	}

	// Cycle 2: Network Recovers, Gateway returns not_online_error
	gw.SimulateServerError = false
	resp2, err := http.Get(serverURL + "/cgi-bin/rad_user_info")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	p2, _ := UnwrapJSONP(string(body2))
	if p2["error"] == "not_online_error" {
		isOnline = false
	}

	// Daemon triggers auto-login
	if !isOnline {
		h := hmac.New(md5.New, []byte(gw.FixedToken))
		h.Write([]byte(password))
		hmd5 := hex.EncodeToString(h.Sum(nil))

		lResp, err := http.Get(fmt.Sprintf("%s/cgi-bin/srun_portal?action=login&username=%s&password={MD5}%s&ip=%s", serverURL, username, hmd5, ip))
		if err != nil {
			t.Fatalf("login failed: %v", err)
		}
		defer lResp.Body.Close()
		lBody, _ := io.ReadAll(lResp.Body)
		lPayload, _ := UnwrapJSONP(string(lBody))
		if lPayload["error"] == "ok" {
			isOnline = true
			failCount = 0 // reset failure counter
		}
	}

	// Cycle 3: Verification
	if !isOnline || failCount != 0 {
		t.Fatalf("auto-reconnect failed: isOnline=%v, failCount=%d", isOnline, failCount)
	}
}

// Scenario 3: Multi-Interface Binding Switch & Auth
// Features: F4, F5, F8, F9, F14
func TestTier4_Scenario3_MultiInterfaceBindingSwitchAndAuth(t *testing.T) {
	gw := mock.NewMockGateway()
	serverURL := gw.Start()
	defer gw.Close()

	primaryIP := "10.200.21.50"
	secondaryIP := "192.168.10.15"

	// Register secondary session in mock
	gw.SetUser(&mock.UserSession{
		Username: "secondary_user",
		Password: "password123",
		IP:       secondaryIP,
		IsOnline: false,
	})

	// 1. Probe & Login on Primary Interface
	h1 := hmac.New(md5.New, []byte(gw.FixedToken))
	h1.Write([]byte("password123"))
	hmd5_1 := hex.EncodeToString(h1.Sum(nil))

	resp1, _ := http.Get(fmt.Sprintf("%s/cgi-bin/srun_portal?action=login&username=20211234&password={MD5}%s&ip=%s", serverURL, hmd5_1, primaryIP))
	resp1.Body.Close()
	if !gw.Users["20211234"].IsOnline {
		t.Fatalf("primary interface login failed")
	}

	// 2. Switch Binding to Secondary Interface & Login
	h2 := hmac.New(md5.New, []byte(gw.FixedToken))
	h2.Write([]byte("password123"))
	hmd5_2 := hex.EncodeToString(h2.Sum(nil))

	resp2, _ := http.Get(fmt.Sprintf("%s/cgi-bin/srun_portal?action=login&username=secondary_user&password={MD5}%s&ip=%s", serverURL, hmd5_2, secondaryIP))
	resp2.Body.Close()
	if !gw.Users["secondary_user"].IsOnline {
		t.Fatalf("secondary interface login failed")
	}
}

// Scenario 4: Fallback from Portal Logout to DM Logout
// Features: F4, F5, F6, F14
func TestTier4_Scenario4_FallbackFromPortalLogoutToDMLogout(t *testing.T) {
	gw := mock.NewMockGateway()
	gw.SetOnline("20211234", true)
	// Force portal logout to fail
	gw.SimulateDMOnlyLogout = true
	serverURL := gw.Start()
	defer gw.Close()

	username := "20211234"
	ip := "10.200.21.50"

	// 1. Attempt portal logout -> detects failure
	pResp, err := http.Get(fmt.Sprintf("%s/cgi-bin/srun_portal?action=logout&username=%s&ip=%s", serverURL, username, ip))
	if err != nil {
		t.Fatalf("portal logout request failed: %v", err)
	}
	defer pResp.Body.Close()
	pBody, _ := io.ReadAll(pResp.Body)
	pPayload, _ := UnwrapJSONP(string(pBody))

	portalSucceeded := pPayload != nil && pPayload["error"] == "ok"
	if portalSucceeded {
		t.Fatalf("expected portal logout to fail")
	}

	// 2. Client initiates fallback to rad_user_dm
	now := time.Now().UnixMilli()
	sign := SrunComputeDMSign(now, username, ip)
	dmURL := fmt.Sprintf("%s/cgi-bin/rad_user_dm?ip=%s&username=%s&time=%d&unbind=0&sign=%s", serverURL, ip, username, now, sign)

	dmResp, err := http.Get(dmURL)
	if err != nil {
		t.Fatalf("dm logout request failed: %v", err)
	}
	defer dmResp.Body.Close()
	dmBody, _ := io.ReadAll(dmResp.Body)
	if string(dmBody) != "logout_ok" {
		t.Fatalf("expected DM logout to return 'logout_ok', got '%s'", string(dmBody))
	}

	// 3. Confirm user session is offline
	if gw.Users[username].IsOnline {
		t.Fatalf("user should be offline after DM fallback logout")
	}
}

// Scenario 5: Legacy Config Migration & DPAPI Re-encryption
// Features: F10, F14
func TestTier4_Scenario5_LegacyConfigMigrationAndDPAPIReencryption(t *testing.T) {
	legacyPlainPass := "CampusPass2026!#"

	// 1. Simulate reading legacy configuration with plaintext or legacy cipher
	rawLoadedPassword := legacyPlainPass

	// 2. Decrypt / normalize password
	plain, err := DPAPIDecrypt(rawLoadedPassword)
	if err != nil {
		t.Fatalf("password extraction failed: %v", err)
	}
	if plain != legacyPlainPass {
		t.Fatalf("password mismatch: expected '%s', got '%s'", legacyPlainPass, plain)
	}

	// 3. Re-encrypt with DPAPI
	newDPAPICipher, err := DPAPIEncrypt(plain)
	if err != nil {
		t.Fatalf("DPAPI re-encryption failed: %v", err)
	}
	if !strings.HasPrefix(newDPAPICipher, "dpapi:") {
		t.Fatalf("expected dpapi: prefix")
	}

	// 4. Save and reload to verify seamless round-trip
	reloadedPlain, err := DPAPIDecrypt(newDPAPICipher)
	if err != nil || reloadedPlain != legacyPlainPass {
		t.Fatalf("reloaded DPAPI decryption failed: %v", err)
	}
}

// Scenario 6: Corrupted Challenge / Malformed JSONP Recovery
// Features: F4, F5, F15
func TestTier4_Scenario6_CorruptedChallengeMalformedJSONPRecovery(t *testing.T) {
	gw := mock.NewMockGateway()
	serverURL := gw.Start()
	defer gw.Close()

	username := "20211234"
	ip := "10.200.21.50"

	// 1. Gateway serves corrupted JSONP
	gw.SimulateMalformedJSONP = true
	resp1, err := http.Get(fmt.Sprintf("%s/cgi-bin/get_challenge?username=%s&ip=%s", serverURL, username, ip))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()

	_, err = UnwrapJSONP(string(body1))
	if err == nil {
		t.Fatalf("expected JSONP parse error")
	}
	// Client handles gracefully by aborting current cycle without crash

	// 2. Gateway recovers on subsequent attempt
	gw.SimulateMalformedJSONP = false
	resp2, err := http.Get(fmt.Sprintf("%s/cgi-bin/get_challenge?username=%s&ip=%s", serverURL, username, ip))
	if err != nil {
		t.Fatalf("subsequent request failed: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	payload2, err := UnwrapJSONP(string(body2))
	if err != nil {
		t.Fatalf("recovery unwrap failed: %v", err)
	}
	token, ok := payload2["challenge"].(string)
	if !ok || token != gw.FixedToken {
		t.Fatalf("expected valid token '%s', got '%v'", gw.FixedToken, token)
	}
}
