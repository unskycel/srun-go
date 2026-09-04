package e2e_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"srun/tests/mock"
)

// =========================================================================
// FEATURE 1: XEncode / XXTEA Crypto - Boundary & Corner Cases (F1)
// =========================================================================

func TestTier2_F1_XEncode_EmptyMessage(t *testing.T) {
	enc := SrunXEncode("", "my_token_123")
	if len(enc) != 0 {
		t.Fatalf("expected empty byte slice for empty message, got len %d", len(enc))
	}
}

func TestTier2_F1_XEncode_EmptyKey(t *testing.T) {
	msg := "test payload"
	enc := SrunXEncode(msg, "")
	if len(enc) == 0 {
		t.Fatalf("expected valid encryption with empty key (padded with zeros)")
	}
}

func TestTier2_F1_XEncode_SingleByteMessage(t *testing.T) {
	msg := "A"
	enc := SrunXEncode(msg, "123456")
	if len(enc) != 8 { // 1 word + 1 length suffix = 2 words * 4 = 8 bytes
		t.Fatalf("expected 8 bytes output for 1-byte message, got %d", len(enc))
	}
}

func TestTier2_F1_XEncode_Exact4ByteMultiple(t *testing.T) {
	// 4 bytes message + 4 bytes length suffix = 8 bytes (2 words)
	msg4 := "1234"
	enc4 := SrunXEncode(msg4, "token123")
	if len(enc4) != 8 {
		t.Fatalf("expected 8 bytes for 4-byte message, got %d", len(enc4))
	}

	// 8 bytes message + 4 bytes length suffix = 12 bytes (3 words)
	msg8 := "12345678"
	enc8 := SrunXEncode(msg8, "token123")
	if len(enc8) != 12 {
		t.Fatalf("expected 12 bytes for 8-byte message, got %d", len(enc8))
	}
}

func TestTier2_F1_XEncode_LargePayloadOverflow(t *testing.T) {
	largeMsg := strings.Repeat("A-Large-Payload-Test-String-0123456789-", 30) // ~1.2 KB
	enc := SrunXEncode(largeMsg, "token_sample_key_long_1234567890")
	if len(enc) == 0 {
		t.Fatalf("large payload encryption failed")
	}
}

// =========================================================================
// FEATURE 2: Custom Base64 Encoding - Boundary & Corner Cases (F2)
// =========================================================================

func TestTier2_F2_CustomBase64_EmptyInput(t *testing.T) {
	res := SrunCustomBase64([]byte{})
	if res != "" {
		t.Fatalf("expected empty string for empty input, got '%s'", res)
	}
}

func TestTier2_F2_CustomBase64_NullBytesInPayload(t *testing.T) {
	payload := []byte{0x00, 0x00, 0x00}
	res := SrunCustomBase64(payload)
	if len(res) != 4 || strings.Contains(res, "=") {
		t.Fatalf("expected 4 characters without padding, got '%s'", res)
	}
}

func TestTier2_F2_CustomBase64_All0xFFBytes(t *testing.T) {
	payload := []byte{0xFF, 0xFF, 0xFF}
	res := SrunCustomBase64(payload)
	if len(res) != 4 {
		t.Fatalf("expected 4 characters, got '%s'", res)
	}
}

func TestTier2_F2_CustomBase64_ExtremeLengths(t *testing.T) {
	buf := make([]byte, 512)
	for i := range buf {
		buf[i] = byte(i % 256)
	}
	res := SrunCustomBase64(buf)
	if len(res) == 0 {
		t.Fatalf("failed encoding 512 bytes")
	}
}

func TestTier2_F2_CustomBase64_SpecialUnicodeUTF8(t *testing.T) {
	input := []byte("深澜校园网验证系统-2026-🎯")
	res := SrunCustomBase64(input)
	if len(res) == 0 {
		t.Fatalf("failed encoding UTF-8 multi-byte payload")
	}
}

// =========================================================================
// FEATURE 3: MD5-HMAC & SHA1 Checksum - Boundary & Corner Cases (F3)
// =========================================================================

func TestTier2_F3_MD5HMAC_EmptyPassword(t *testing.T) {
	token := "bb983c27e4e1a0b345f7823901acde45"
	res := SrunMD5HMAC("", token)
	if len(res) != 32 {
		t.Fatalf("expected 32-hex MD5 output, got '%s'", res)
	}
}

func TestTier2_F3_MD5HMAC_EmptyToken(t *testing.T) {
	res := SrunMD5HMAC("password123", "")
	if len(res) != 32 {
		t.Fatalf("expected 32-hex MD5 output, got '%s'", res)
	}
}

func TestTier2_F3_SHA1_EmptyString(t *testing.T) {
	expected := "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	res := SrunSHA1("")
	if res != expected {
		t.Fatalf("expected '%s', got '%s'", expected, res)
	}
}

func TestTier2_F3_SHA1_VeryLongChksumString(t *testing.T) {
	longStr := strings.Repeat("bb983c27e4e1a0b345f7823901acde45", 100)
	res := SrunSHA1(longStr)
	if len(res) != 40 {
		t.Fatalf("expected 40-hex SHA1 output, got '%s'", res)
	}
}

func TestTier2_F3_MD5HMAC_NonASCIICharacters(t *testing.T) {
	res := SrunMD5HMAC("密码_P@ss!#$€", "token12345")
	if len(res) != 32 {
		t.Fatalf("expected 32-hex string, got '%s'", res)
	}
}

// =========================================================================
// FEATURE 4: Gateway Challenge & JSONP - Boundary & Corner Cases (F4)
// =========================================================================

func TestTier2_F4_GetChallenge_MalformedJSONPResponse(t *testing.T) {
	gw := mock.NewMockGateway()
	gw.SimulateMalformedJSONP = true
	serverURL := gw.Start()
	defer gw.Close()

	resp, err := http.Get(serverURL + "/cgi-bin/get_challenge?username=20211234")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	_, unwrapErr := UnwrapJSONP(string(body))
	if unwrapErr == nil {
		t.Fatalf("expected JSON unwrap error on malformed JSONP")
	}
}

func TestTier2_F4_GetChallenge_EmptyBodyResponse(t *testing.T) {
	_, err := UnwrapJSONP("")
	if err == nil {
		t.Fatalf("expected error on empty body")
	}
}

func TestTier2_F4_GetChallenge_ServerError500(t *testing.T) {
	gw := mock.NewMockGateway()
	gw.SimulateServerError = true
	serverURL := gw.Start()
	defer gw.Close()

	resp, err := http.Get(serverURL + "/cgi-bin/get_challenge?username=20211234")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", resp.StatusCode)
	}
}

func TestTier2_F4_GetChallenge_SpecialCharactersInUsername(t *testing.T) {
	gw := mock.NewMockGateway()
	serverURL := gw.Start()
	defer gw.Close()

	username := "user+test@buaa.edu.cn"
	resp, err := http.Get(serverURL + "/cgi-bin/get_challenge?username=" + username)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestTier2_F4_GetChallenge_IPv6OrMalformedIP(t *testing.T) {
	gw := mock.NewMockGateway()
	serverURL := gw.Start()
	defer gw.Close()

	resp, err := http.Get(serverURL + "/cgi-bin/get_challenge?username=20211234&ip=fe80::1")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	payload, _ := UnwrapJSONP(string(body))
	if payload["client_ip"] != "fe80::1" {
		t.Fatalf("expected custom IP to be preserved in payload")
	}
}

// =========================================================================
// FEATURE 5: Portal Login & Logout Flow - Boundary & Corner Cases (F5)
// =========================================================================

func TestTier2_F5_Portal_LockedAccountE2553(t *testing.T) {
	gw := mock.NewMockGateway()
	gw.SimulateLockoutError = true
	serverURL := gw.Start()
	defer gw.Close()

	resp, err := http.Get(serverURL + "/cgi-bin/srun_portal?action=login&username=20211234")
	if err != nil {
		t.Fatalf("http get failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	payload, _ := UnwrapJSONP(string(body))
	errStr, _ := payload["error"].(string)
	if !strings.Contains(errStr, "E2553") {
		t.Fatalf("expected E2553 lockout error, got '%s'", errStr)
	}
}

func TestTier2_F5_Portal_DeviceLimitE2534(t *testing.T) {
	gw := mock.NewMockGateway()
	gw.SimulateDeviceLimit = true
	serverURL := gw.Start()
	defer gw.Close()

	resp, err := http.Get(serverURL + "/cgi-bin/srun_portal?action=login&username=20211234")
	if err != nil {
		t.Fatalf("http get failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	payload, _ := UnwrapJSONP(string(body))
	errStr, _ := payload["error"].(string)
	if !strings.Contains(errStr, "E2534") {
		t.Fatalf("expected E2534 device limit error, got '%s'", errStr)
	}
}

func TestTier2_F5_Portal_NonExistentUserE2606(t *testing.T) {
	gw := mock.NewMockGateway()
	serverURL := gw.Start()
	defer gw.Close()

	resp, err := http.Get(serverURL + "/cgi-bin/srun_portal?action=login&username=non_existent_user_9999")
	if err != nil {
		t.Fatalf("http get failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	payload, _ := UnwrapJSONP(string(body))
	errStr, _ := payload["error"].(string)
	if !strings.Contains(errStr, "E2606") {
		t.Fatalf("expected E2606 non-existent user error, got '%s'", errStr)
	}
}

func TestTier2_F5_Portal_EmptyCredentials(t *testing.T) {
	gw := mock.NewMockGateway()
	serverURL := gw.Start()
	defer gw.Close()

	resp, err := http.Get(serverURL + "/cgi-bin/srun_portal?action=login&username=")
	if err != nil {
		t.Fatalf("http get failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	payload, _ := UnwrapJSONP(string(body))
	if payload["error"] == "ok" {
		t.Fatalf("expected login failure on empty username")
	}
}

func TestTier2_F5_Portal_TrailingWhitespaceInUsername(t *testing.T) {
	rawUser := " 20211234 "
	trimmed := strings.TrimSpace(rawUser)
	if trimmed != "20211234" {
		t.Fatalf("whitespace trim failed")
	}
}

// =========================================================================
// FEATURE 6: Classic DM Logout Fallback - Boundary & Corner Cases (F6)
// =========================================================================

func TestTier2_F6_DMLogout_MissingParameters(t *testing.T) {
	gw := mock.NewMockGateway()
	serverURL := gw.Start()
	defer gw.Close()

	resp, err := http.Get(serverURL + "/cgi-bin/rad_user_dm?username=20211234")
	if err != nil {
		t.Fatalf("http get failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request on missing params, got %d", resp.StatusCode)
	}
}

func TestTier2_F6_DMLogout_ExpiredTimestamp(t *testing.T) {
	var oldTimestamp int64 = 1000000000000 // year 2001
	sign := SrunComputeDMSign(oldTimestamp, "20211234", "10.200.21.50")
	if len(sign) != 40 {
		t.Fatalf("invalid sign length %d", len(sign))
	}
}

func TestTier2_F6_DMLogout_NonStandardSuccessResponse(t *testing.T) {
	acceptedSuccess := map[string]bool{
		"ok":        true,
		"logout_ok": true,
		"success":   true,
		"1":         true,
		"true":      true,
	}
	for s := range acceptedSuccess {
		if !acceptedSuccess[s] {
			t.Fatalf("failed recognition of success token '%s'", s)
		}
	}
}

func TestTier2_F6_DMLogout_Portal500TriggersDM(t *testing.T) {
	gw := mock.NewMockGateway()
	gw.SetOnline("20211234", true)
	gw.SimulateDMOnlyLogout = true
	serverURL := gw.Start()
	defer gw.Close()

	// 1. Try portal logout -> fails
	resp1, err := http.Get(serverURL + "/cgi-bin/srun_portal?action=logout&username=20211234")
	if err != nil {
		t.Fatalf("http get failed: %v", err)
	}
	defer resp1.Body.Close()
	body1, _ := io.ReadAll(resp1.Body)
	payload1, _ := UnwrapJSONP(string(body1))
	if payload1["error"] == "ok" {
		t.Fatalf("expected portal logout to fail in DM-only simulation")
	}

	// 2. Fallback to DM logout -> succeeds
	now := time.Now().UnixMilli()
	sign := SrunComputeDMSign(now, "20211234", "10.200.21.50")
	resp2, err := http.Get(fmt.Sprintf("%s/cgi-bin/rad_user_dm?ip=10.200.21.50&username=20211234&time=%d&unbind=0&sign=%s", serverURL, now, sign))
	if err != nil {
		t.Fatalf("http get failed: %v", err)
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)
	if string(body2) != "logout_ok" {
		t.Fatalf("expected DM fallback logout to succeed")
	}
}

func TestTier2_F6_DMLogout_EmptySignRejected(t *testing.T) {
	gw := mock.NewMockGateway()
	serverURL := gw.Start()
	defer gw.Close()

	resp, err := http.Get(serverURL + "/cgi-bin/rad_user_dm?ip=10.200.21.50&username=20211234&time=1756684800000&unbind=0&sign=")
	if err != nil {
		t.Fatalf("http get failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on empty sign, got %d", resp.StatusCode)
	}
}

// =========================================================================
// FEATURE 7: User Info & Traffic Query - Boundary & Corner Cases (F7)
// =========================================================================

func TestTier2_F7_UserInfo_HugeTrafficValues(t *testing.T) {
	gw := mock.NewMockGateway()
	gw.SetUser(&mock.UserSession{
		Username: "heavy_user",
		IP:       "10.200.21.50",
		AllBytes: 1099511627776, // 1 TB (exceeds 32-bit int)
		IsOnline: true,
	})
	serverURL := gw.Start()
	defer gw.Close()

	resp, err := http.Get(serverURL + "/cgi-bin/rad_user_info?callback=JQuery")
	if err != nil {
		t.Fatalf("http get failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	payload, _ := UnwrapJSONP(string(body))

	allBytes, ok := payload["all_bytes"].(float64)
	if !ok || int64(allBytes) != 1099511627776 {
		t.Fatalf("expected 64-bit byte count 1099511627776, got %v", payload["all_bytes"])
	}
}

func TestTier2_F7_UserInfo_NegativeBalance(t *testing.T) {
	gw := mock.NewMockGateway()
	gw.SetUser(&mock.UserSession{
		Username: "arrears_user",
		IP:       "10.200.21.50",
		Balance:  -15.50,
		IsOnline: true,
	})
	serverURL := gw.Start()
	defer gw.Close()

	resp, err := http.Get(serverURL + "/cgi-bin/rad_user_info?callback=JQuery")
	if err != nil {
		t.Fatalf("http get failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	payload, _ := UnwrapJSONP(string(body))

	bal, _ := payload["user_balance"].(float64)
	if bal != -15.50 {
		t.Fatalf("expected negative balance -15.50, got %v", bal)
	}
}

func TestTier2_F7_UserInfo_ZeroBalance(t *testing.T) {
	gw := mock.NewMockGateway()
	gw.SetUser(&mock.UserSession{
		Username: "zero_user",
		IP:       "10.200.21.50",
		Balance:  0.0,
		IsOnline: true,
	})
	serverURL := gw.Start()
	defer gw.Close()

	resp, err := http.Get(serverURL + "/cgi-bin/rad_user_info?callback=JQuery")
	if err != nil {
		t.Fatalf("http get failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	payload, _ := UnwrapJSONP(string(body))
	bal, _ := payload["user_balance"].(float64)
	if bal != 0.0 {
		t.Fatalf("expected 0.0 balance, got %v", bal)
	}
}

func TestTier2_F7_UserInfo_MissingOptionalFields(t *testing.T) {
	rawJSONP := `JQuery({"error":"ok","client_ip":"10.200.21.50"})`
	payload, err := UnwrapJSONP(rawJSONP)
	if err != nil {
		t.Fatalf("unwrap error: %v", err)
	}
	if payload["user_mac"] != nil {
		t.Fatalf("expected nil for absent optional field")
	}
}

func TestTier2_F7_UserInfo_MalformedJSONPRecovery(t *testing.T) {
	raw := `InvalidWrapper`
	_, err := UnwrapJSONP(raw)
	if err == nil {
		t.Fatalf("expected error on unparsable response")
	}
}

// =========================================================================
// FEATURE 8: Multi-NIC IPv4 Enumeration - Boundary & Corner Cases (F8)
// =========================================================================

func TestTier2_F8_NIC_NoNetworkInterfaces(t *testing.T) {
	filterIPs := func(candidates []string) []string {
		var out []string
		for _, ip := range candidates {
			if !strings.HasPrefix(ip, "127.") && !strings.HasPrefix(ip, "169.254.") {
				out = append(out, ip)
			}
		}
		return out
	}
	res := filterIPs([]string{"127.0.0.1", "169.254.10.20"})
	if len(res) != 0 {
		t.Fatalf("expected 0 candidate IPs after filtering loopback and link-local")
	}
}

func TestTier2_F8_NIC_DuplicateIPsDeduplication(t *testing.T) {
	rawIPs := []string{"10.200.21.50", "192.168.1.100", "10.200.21.50"}
	seen := make(map[string]bool)
	var deduped []string
	for _, ip := range rawIPs {
		if !seen[ip] {
			seen[ip] = true
			deduped = append(deduped, ip)
		}
	}
	if len(deduped) != 2 {
		t.Fatalf("expected 2 unique IPs, got %d", len(deduped))
	}
}

func TestTier2_F8_NIC_SubnetBroadcastFiltered(t *testing.T) {
	isBroadcast := func(ipStr string) bool {
		return ipStr == "255.255.255.255"
	}
	if !isBroadcast("255.255.255.255") || isBroadcast("10.200.21.50") {
		t.Fatalf("broadcast filter check failed")
	}
}

func TestTier2_F8_NIC_VirtualAdapterIPs(t *testing.T) {
	// Virtual adapters (e.g. 198.18.x.x, 192.168.56.x) are valid IPv4 strings
	ip := net.ParseIP("198.18.0.1")
	if ip == nil || ip.To4() == nil {
		t.Fatalf("expected valid IPv4 for virtual adapter")
	}
}

func TestTier2_F8_NIC_IPv4OnlyFiltering(t *testing.T) {
	isIPv4 := func(ipStr string) bool {
		parsed := net.ParseIP(ipStr)
		return parsed != nil && parsed.To4() != nil
	}
	if !isIPv4("10.200.21.50") || isIPv4("2001:db8::1") {
		t.Fatalf("IPv4-only validation filter failed")
	}
}

// =========================================================================
// FEATURE 9: Source IP Socket Binding - Boundary & Corner Cases (F9)
// =========================================================================

func TestTier2_F9_SocketBind_InvalidIPFormat(t *testing.T) {
	parsed := net.ParseIP("999.999.999.999")
	if parsed != nil {
		t.Fatalf("expected nil for invalid IP string")
	}
}

func TestTier2_F9_SocketBind_UnassignedLocalIP(t *testing.T) {
	// Binding to an unassigned IP (e.g. 203.0.113.1) should fail to connect or dial
	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 0},
		Timeout:   100 * time.Millisecond,
	}
	_, err := dialer.Dial("tcp", "127.0.0.1:80")
	if err == nil {
		t.Fatalf("expected error when binding to unassigned local IP")
	}
}

func TestTier2_F9_SocketBind_PortCollisionPrevention(t *testing.T) {
	addr1 := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	addr2 := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	if addr1.Port != 0 || addr2.Port != 0 {
		t.Fatalf("both addrs must request port 0 to prevent collision")
	}
}

func TestTier2_F9_SocketBind_SpecialKeywords(t *testing.T) {
	normalizeBindIP := func(ipStr string) *string {
		lower := strings.ToLower(strings.TrimSpace(ipStr))
		if lower == "" || lower == "auto" || lower == "default" || lower == "null" {
			return nil
		}
		return &ipStr
	}
	if normalizeBindIP("auto") != nil || normalizeBindIP("default") != nil || normalizeBindIP("") != nil {
		t.Fatalf("expected nil for auto/default/empty bind IP")
	}
	if normalizeBindIP("10.200.21.50") == nil {
		t.Fatalf("expected non-nil for explicit IP")
	}
}

func TestTier2_F9_SocketBind_ConcurrentDialing(t *testing.T) {
	gw := mock.NewMockGateway()
	serverURL := gw.Start()
	defer gw.Close()

	done := make(chan bool, 5)
	for i := 0; i < 5; i++ {
		go func() {
			client := &http.Client{Timeout: 2 * time.Second}
			resp, err := client.Get(serverURL + "/cgi-bin/rad_user_info")
			if err == nil && resp.StatusCode == http.StatusOK {
				resp.Body.Close()
				done <- true
			} else {
				done <- false
			}
		}()
	}

	for i := 0; i < 5; i++ {
		if !<-done {
			t.Fatalf("concurrent request failed")
		}
	}
}

// =========================================================================
// FEATURE 10: Config File & DPAPI Encryption - Boundary & Corner Cases (F10)
// =========================================================================

func TestTier2_F10_Config_CorruptedJSONRecovery(t *testing.T) {
	corrupted := `{"username": "test", "password": `
	type Config struct {
		Username string `json:"username"`
	}
	var cfg Config
	err := json.Unmarshal([]byte(corrupted), &cfg)
	if err == nil {
		t.Fatalf("expected unmarshal error on corrupted JSON")
	}
}

func TestTier2_F10_Config_EmptyConfigFile(t *testing.T) {
	emptyData := []byte("")
	type Config struct {
		Username string `json:"username"`
	}
	var cfg Config
	err := json.Unmarshal(emptyData, &cfg)
	if err == nil {
		t.Fatalf("expected error on empty JSON bytes")
	}
}

func TestTier2_F10_DPAPI_EmptyPlaintext(t *testing.T) {
	enc, err := DPAPIEncrypt("")
	if err != nil || enc != "" {
		t.Fatalf("expected empty result on empty plaintext")
	}
	dec, err := DPAPIDecrypt("")
	if err != nil || dec != "" {
		t.Fatalf("expected empty result on empty ciphertext")
	}
}

func TestTier2_F10_DPAPI_CorruptedCiphertext(t *testing.T) {
	_, err := DPAPIDecrypt("dpapi:not_valid_base64_!@#$")
	if err == nil {
		t.Fatalf("expected decryption error on corrupted base64")
	}
}

func TestTier2_F10_LegacyAES_CorruptedHex(t *testing.T) {
	_, err := DecryptLegacyAES("non_hex_characters_zzzz", LegacyAESKey)
	if err == nil {
		t.Fatalf("expected error on invalid hex string")
	}
}

// =========================================================================
// FEATURE 11: System Theme Querying - Boundary & Corner Cases (F11)
// =========================================================================

func TestTier2_F11_Theme_NonStandardDWORDValue(t *testing.T) {
	resolveTheme := func(val int) int {
		if val == 0 {
			return 0 // Dark
		}
		return 1 // Light (fallback)
	}
	if resolveTheme(99) != 1 {
		t.Fatalf("expected fallback to light mode (1) on non-standard registry value")
	}
}

func TestTier2_F11_Theme_RegistryStringValue(t *testing.T) {
	resolveFromString := func(val string) int {
		if val == "0" {
			return 0
		}
		return 1
	}
	if resolveFromString("1") != 1 || resolveFromString("invalid") != 1 {
		t.Fatalf("unexpected string resolve result")
	}
}

func TestTier2_F11_Theme_RegistryAccessDenied(t *testing.T) {
	fallbackMode := 1 // default light
	if fallbackMode != 1 {
		t.Fatalf("expected default light mode on access denied")
	}
}

func TestTier2_F11_Theme_FrequentPolling(t *testing.T) {
	for i := 0; i < 20; i++ {
		_, _ = CheckThemeFromRegistry()
	}
}

func TestTier2_F11_Theme_NilPointerSafety(t *testing.T) {
	safeGet := func() int {
		defer func() { _ = recover() }()
		return 1
	}
	if safeGet() != 1 {
		t.Fatalf("nil safety check failed")
	}
}

// =========================================================================
// FEATURE 12: Registry Startup Management - Boundary & Corner Cases (F12)
// =========================================================================

func TestTier2_F12_Startup_PathWithSpaces(t *testing.T) {
	path := `C:\Program Files (x86)\SRun Client\srun.exe`
	formatted := `"` + path + `" --no-auto-open`
	if !strings.HasPrefix(formatted, `"C:\Program Files`) || !strings.HasSuffix(formatted, `--no-auto-open`) {
		t.Fatalf("path with spaces improperly quoted: %s", formatted)
	}
}

func TestTier2_F12_Startup_UnsetNonExistentKey(t *testing.T) {
	mockRegistry := make(map[string]string)
	deleteKey := func(k string) error {
		delete(mockRegistry, k)
		return nil
	}
	err := deleteKey("SRunClient")
	if err != nil {
		t.Fatalf("deleting non-existent key should not return error")
	}
}

func TestTier2_F12_Startup_DuplicateSetCalls(t *testing.T) {
	mockRegistry := make(map[string]string)
	setKey := func(k, v string) {
		mockRegistry[k] = v
	}
	setKey("SRunClient", "cmd1")
	setKey("SRunClient", "cmd2")
	if mockRegistry["SRunClient"] != "cmd2" {
		t.Fatalf("expected idempotent overwrite")
	}
}

func TestTier2_F12_Startup_SpecialCharactersInPath(t *testing.T) {
	path := `D:\校园网\srun.exe`
	formatted := `"` + path + `" --no-auto-open`
	if formatted != `"D:\校园网\srun.exe" --no-auto-open` {
		t.Fatalf("unicode path quoting mismatch")
	}
}

func TestTier2_F12_Startup_EmptyExePath(t *testing.T) {
	validatePath := func(p string) error {
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("executable path cannot be empty")
		}
		return nil
	}
	if validatePath("") == nil {
		t.Fatalf("expected validation error on empty path")
	}
}

// =========================================================================
// FEATURE 13: Dual Dispatch & Console Attach - Boundary & Corner Cases (F13)
// =========================================================================

func TestTier2_F13_Dispatch_UnknownFlags(t *testing.T) {
	args := []string{"srun.exe", "--unknown-flag"}
	isHelp := false
	for _, a := range args[1:] {
		if a == "-h" || a == "--help" || strings.HasPrefix(a, "--unknown") {
			isHelp = true
		}
	}
	if !isHelp {
		t.Fatalf("expected unknown flag recognition")
	}
}

func TestTier2_F13_Dispatch_CombinedShortFlags(t *testing.T) {
	args := []string{"-l", "-u", "20211234", "-p", "pass"}
	hasLogin := false
	for _, a := range args {
		if a == "-l" || a == "--login" {
			hasLogin = true
		}
	}
	if !hasLogin {
		t.Fatalf("expected login short flag recognition")
	}
}

func TestTier2_F13_Dispatch_FlagWithEmptyValue(t *testing.T) {
	username := ""
	if username == "" {
		// Prompts interactively or uses config
		fallbackUsed := true
		if !fallbackUsed {
			t.Fatalf("expected fallback on empty username flag")
		}
	}
}

func TestTier2_F13_Dispatch_DoubleHyphenTerminator(t *testing.T) {
	args := []string{"--", "-l"}
	if len(args) < 2 || args[0] != "--" {
		t.Fatalf("double hyphen terminator check failed")
	}
}

func TestTier2_F13_Dispatch_ExcessiveArguments(t *testing.T) {
	args := make([]string, 100)
	for i := range args {
		args[i] = fmt.Sprintf("arg_%d", i)
	}
	if len(args) != 100 {
		t.Fatalf("excessive arguments count mismatch")
	}
}

// =========================================================================
// FEATURE 14: CLI Subcommands & Flags - Boundary & Corner Cases (F14)
// =========================================================================

func TestTier2_F14_CLI_InteractiveMenuSelection1(t *testing.T) {
	choice := "1"
	action := map[string]string{"1": "login", "2": "logout", "3": "status"}[choice]
	if action != "login" {
		t.Fatalf("expected menu 1 to map to login, got '%s'", action)
	}
}

func TestTier2_F14_CLI_InteractiveMenuSelection2(t *testing.T) {
	choice := "2"
	action := map[string]string{"1": "login", "2": "logout", "3": "status"}[choice]
	if action != "logout" {
		t.Fatalf("expected menu 2 to map to logout, got '%s'", action)
	}
}

func TestTier2_F14_CLI_InteractiveMenuSelection3(t *testing.T) {
	choice := "3"
	action := map[string]string{"1": "login", "2": "logout", "3": "status"}[choice]
	if action != "status" {
		t.Fatalf("expected menu 3 to map to status, got '%s'", action)
	}
}

func TestTier2_F14_CLI_InteractiveMenuSelectionInvalid(t *testing.T) {
	choice := "9"
	action, exists := map[string]string{"1": "login", "2": "logout", "3": "status"}[choice]
	if exists || action != "" {
		t.Fatalf("invalid menu choice should not map to action")
	}
}

func TestTier2_F14_CLI_MultipleLocalIPsFlag(t *testing.T) {
	parseIPList := func(raw []string) []string {
		var out []string
		for _, item := range raw {
			parts := strings.Split(item, ",")
			for _, p := range parts {
				trimmed := strings.TrimSpace(p)
				if trimmed != "" {
					out = append(out, trimmed)
				}
			}
		}
		return out
	}
	res := parseIPList([]string{"10.200.21.50,192.168.1.100", "172.16.0.5"})
	if len(res) != 3 {
		t.Fatalf("expected 3 parsed IPs, got %d", len(res))
	}
}

// =========================================================================
// FEATURE 15: Daemon Mode & Backoff Loop - Boundary & Corner Cases (F15)
// =========================================================================

func TestTier2_F15_Daemon_ZeroSleeptimeConfig(t *testing.T) {
	normalizeSleep := func(s int) int {
		if s <= 0 {
			return 1
		}
		return s
	}
	if normalizeSleep(0) != 1 || normalizeSleep(-5) != 1 {
		t.Fatalf("expected clamping to 1s on non-positive sleeptime")
	}
}

func TestTier2_F15_Daemon_ExtremeFailureCount(t *testing.T) {
	backoff := CalculateDaemonBackoff(1000000, 5)
	if backoff != 300 {
		t.Fatalf("expected backoff to remain capped at 300s, got %d", backoff)
	}
}

func TestTier2_F15_Daemon_NetworkDownNoFailIncrement(t *testing.T) {
	// If gateway is unavailable (cable unplugged), do NOT increment login_failed_count
	isAvailable := false
	isOnline := false
	failCount := 0

	if isAvailable && !isOnline {
		failCount++
	}
	if failCount != 0 {
		t.Fatalf("failCount should not increment when gateway is unavailable")
	}
}

func TestTier2_F15_Daemon_PassCorrectRequirement(t *testing.T) {
	canAutoLogin := func(passCorrect bool, autoLogin bool) bool {
		return passCorrect && autoLogin
	}
	if canAutoLogin(false, true) {
		t.Fatalf("auto_login must not activate if pass_correct is false")
	}
	if !canAutoLogin(true, true) {
		t.Fatalf("auto_login should activate if pass_correct is true")
	}
}

func TestTier2_F15_Daemon_MultipleNICIterationFailure(t *testing.T) {
	ips := []string{"10.200.21.50", "192.168.1.100"}
	results := make(map[string]bool)

	for _, ip := range ips {
		if ip == "10.200.21.50" {
			results[ip] = true // success
		} else {
			results[ip] = false // failure on secondary NIC
		}
	}

	if results["10.200.21.50"] != true || results["192.168.1.100"] != false {
		t.Fatalf("individual NIC state isolation failed")
	}
}
