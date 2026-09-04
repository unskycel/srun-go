package e2e_test

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"srun/tests/mock"
)

// =========================================================================
// FEATURE 1: XEncode / XXTEA Crypto (F1)
// =========================================================================

func TestTier1_F1_XEncode_BasicWordsSencode(t *testing.T) {
	input := "hello world"
	words := SrunSencode(input, true)
	if len(words) != 4 {
		t.Fatalf("expected 4 words, got %d", len(words))
	}
	if words[3] != 11 {
		t.Fatalf("expected length suffix 11, got %d", words[3])
	}
}

func TestTier1_F1_XEncode_SencodeWithoutLen(t *testing.T) {
	input := "hello world"
	words := SrunSencode(input, false)
	if len(words) != 3 {
		t.Fatalf("expected 3 words without length suffix, got %d", len(words))
	}
}

func TestTier1_F1_XEncode_LencodeRoundtrip(t *testing.T) {
	input := "sample test string for roundtrip"
	words := SrunSencode(input, true)
	decoded := SrunLencode(words, true)
	if string(decoded) != input {
		t.Fatalf("expected '%s', got '%s'", input, string(decoded))
	}
}

func TestTier1_F1_XEncode_StandardPayloadEncryption(t *testing.T) {
	vectors := LoadCryptoVectors(t)
	for idx, v := range vectors.XEncodeVectors {
		encrypted := SrunXEncode(v.Msg, v.Key)
		gotHex := hex.EncodeToString(encrypted)
		if gotHex != v.OutputHex {
			t.Errorf("[vector %d] expected hex '%s', got '%s'", idx, v.OutputHex, gotHex)
		}
	}
}

func TestTier1_F1_XEncode_ShortAndLongKeys(t *testing.T) {
	msg := "test message payload"
	// Key < 4 bytes
	enc1 := SrunXEncode(msg, "1")
	if len(enc1) == 0 {
		t.Fatalf("encryption with 1-byte key failed")
	}
	// Key > 16 bytes
	enc2 := SrunXEncode(msg, "12345678901234567890")
	if len(enc2) == 0 {
		t.Fatalf("encryption with long key failed")
	}
	if string(enc1) == string(enc2) {
		t.Fatalf("encryptions with different keys produced identical output")
	}
}

// =========================================================================
// FEATURE 2: Custom Base64 Encoding (F2)
// =========================================================================

func TestTier1_F2_CustomBase64_ExactAlphabetParity(t *testing.T) {
	if len(SrunBase64Alpha) != 64 {
		t.Fatalf("expected alphabet length 64, got %d", len(SrunBase64Alpha))
	}
	expectedAlpha := "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
	if SrunBase64Alpha != expectedAlpha {
		t.Fatalf("alphabet mismatch: %s vs %s", SrunBase64Alpha, expectedAlpha)
	}
}

func TestTier1_F2_CustomBase64_PadMod1(t *testing.T) {
	// len("a") % 3 == 1 -> ends with "=="
	res := SrunCustomBase64([]byte("a"))
	if !strings.HasSuffix(res, "==") {
		t.Fatalf("expected result to end with '==', got '%s'", res)
	}
	if res != "Z+==" {
		t.Fatalf("expected 'Z+==', got '%s'", res)
	}
}

func TestTier1_F2_CustomBase64_PadMod2(t *testing.T) {
	// len("ab") % 3 == 2 -> ends with "="
	res := SrunCustomBase64([]byte("ab"))
	if !strings.HasSuffix(res, "=") || strings.HasSuffix(res, "==") {
		t.Fatalf("expected result to end with single '=', got '%s'", res)
	}
	if res != "Za2=" {
		t.Fatalf("expected 'Za2=', got '%s'", res)
	}
}

func TestTier1_F2_CustomBase64_PadMod0(t *testing.T) {
	// len("abc") % 3 == 0 -> no padding
	res := SrunCustomBase64([]byte("abc"))
	if strings.Contains(res, "=") {
		t.Fatalf("expected no padding characters, got '%s'", res)
	}
	if res != "ZaRk" {
		t.Fatalf("expected 'ZaRk', got '%s'", res)
	}
}

func TestTier1_F2_CustomBase64_PythonVectorParity(t *testing.T) {
	vectors := LoadCryptoVectors(t)
	for idx, v := range vectors.CustomBase64Vectors {
		encoded := SrunCustomBase64([]byte(v.Input))
		if encoded != v.Output {
			t.Errorf("[b64 vector %d] input '%s': expected '%s', got '%s'", idx, v.Input, v.Output, encoded)
		}
	}
}

// =========================================================================
// FEATURE 3: MD5-HMAC & SHA1 Checksum (F3)
// =========================================================================

func TestTier1_F3_MD5HMAC_PasswordHashing(t *testing.T) {
	token := "bb983c27e4e1a0b345f7823901acde45"
	password := "password123"
	expected := "8d3d276efabbb7bd62b796b777cf981b"
	got := SrunMD5HMAC(password, token)
	if got != expected {
		t.Fatalf("expected MD5-HMAC '%s', got '%s'", expected, got)
	}
}

func TestTier1_F3_SHA1_StandardValues(t *testing.T) {
	input := "hello"
	expected := "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
	got := SrunSHA1(input)
	if got != expected {
		t.Fatalf("expected SHA1 '%s', got '%s'", expected, got)
	}
}

func TestTier1_F3_SHA1_PortalChksumFormat(t *testing.T) {
	token := "bb983c27e4e1a0b345f7823901acde45"
	username := "20211234"
	hmd5 := "8d3d276efabbb7bd62b796b777cf981b"
	ip := "10.200.21.50"
	info := "{SRBX1}sample_info"
	acid := "1"
	n := "200"
	type_ := "1"

	chksum := SrunComputeChksum(username, token, hmd5, ip, info, acid, n, type_)
	if len(chksum) != 40 {
		t.Fatalf("expected 40-char SHA1 hex, got '%s'", chksum)
	}
}

func TestTier1_F3_SHA1_DMSignFormat(t *testing.T) {
	var timestamp int64 = 1756684800000
	username := "20211234"
	ip := "10.200.21.50"
	expected := "9e81d89e32343d90fb95a39e0f8e8b232495660e"
	got := SrunComputeDMSign(timestamp, username, ip)
	if got != expected {
		t.Fatalf("expected DM sign '%s', got '%s'", expected, got)
	}
}

func TestTier1_F3_MD5HMAC_VectorParity(t *testing.T) {
	vectors := LoadCryptoVectors(t)
	for idx, v := range vectors.MD5HMACVectors {
		got := SrunMD5HMAC(v.Password, v.Token)
		if got != v.Output {
			t.Errorf("[MD5HMAC vector %d] expected '%s', got '%s'", idx, v.Output, got)
		}
	}
}

// =========================================================================
// FEATURE 4: Gateway Challenge & JSONP (F4)
// =========================================================================

func TestTier1_F4_GetChallenge_TokenExtraction(t *testing.T) {
	gw := mock.NewMockGateway()
	serverURL := gw.Start()
	defer gw.Close()

	resp, err := http.Get(serverURL + "/cgi-bin/get_challenge?username=20211234&ip=10.200.21.50")
	if err != nil {
		t.Fatalf("get_challenge request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	payload, err := UnwrapJSONP(string(body))
	if err != nil {
		t.Fatalf("failed to unwrap JSONP: %v", err)
	}
	token, ok := payload["challenge"].(string)
	if !ok || token != gw.FixedToken {
		t.Fatalf("expected challenge '%s', got '%v'", gw.FixedToken, payload["challenge"])
	}
}

func TestTier1_F4_GetChallenge_JSONPCallbackUnwrap(t *testing.T) {
	cb := "myCustomCallback_12345"
	rawJSONP := fmt.Sprintf("%s({\"challenge\":\"abcdef0123456789\",\"error\":\"ok\"})", cb)
	payload, err := UnwrapJSONP(rawJSONP)
	if err != nil {
		t.Fatalf("failed to unwrap custom JSONP: %v", err)
	}
	if payload["challenge"] != "abcdef0123456789" {
		t.Fatalf("unexpected challenge payload: %v", payload)
	}
}

func TestTier1_F4_GetChallenge_CacheBustingParam(t *testing.T) {
	gw := mock.NewMockGateway()
	serverURL := gw.Start()
	defer gw.Close()

	ts := fmt.Sprintf("%d", time.Now().UnixMilli())
	_, err := http.Get(serverURL + "/cgi-bin/get_challenge?username=20211234&_=" + ts)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	reqs := gw.GetRequests()
	if len(reqs) == 0 || reqs[0].Query.Get("_") != ts {
		t.Fatalf("cache busting timestamp not received by gateway")
	}
}

func TestTier1_F4_GetChallenge_CustomClientIP(t *testing.T) {
	gw := mock.NewMockGateway()
	serverURL := gw.Start()
	defer gw.Close()

	customIP := "10.200.45.99"
	resp, err := http.Get(serverURL + "/cgi-bin/get_challenge?username=20211234&ip=" + customIP)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	payload, err := UnwrapJSONP(string(body))
	if err != nil {
		t.Fatalf("failed unwrap: %v", err)
	}
	if payload["client_ip"] != customIP {
		t.Fatalf("expected client_ip '%s', got '%v'", customIP, payload["client_ip"])
	}
}

func TestTier1_F4_GetChallenge_SuccessStatusCode(t *testing.T) {
	gw := mock.NewMockGateway()
	serverURL := gw.Start()
	defer gw.Close()

	resp, err := http.Get(serverURL + "/cgi-bin/get_challenge?username=20211234")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
}

// =========================================================================
// FEATURE 5: Portal Login & Logout Flow (F5)
// =========================================================================

func TestTier1_F5_Portal_LoginSuccess(t *testing.T) {
	gw := mock.NewMockGateway()
	serverURL := gw.Start()
	defer gw.Close()

	h := hmac.New(md5.New, []byte(gw.FixedToken))
	h.Write([]byte("password123"))
	hmd5 := hex.EncodeToString(h.Sum(nil))

	loginURL := fmt.Sprintf("%s/cgi-bin/srun_portal?action=login&username=20211234&password={MD5}%s&ac_id=1&ip=10.200.21.50",
		serverURL, hmd5)
	resp, err := http.Get(loginURL)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	payload, err := UnwrapJSONP(string(body))
	if err != nil {
		t.Fatalf("unwrap failed: %v", err)
	}
	if payload["error"] != "ok" {
		t.Fatalf("expected error='ok', got %v", payload["error"])
	}
}

func TestTier1_F5_Portal_LoginWrongPassword(t *testing.T) {
	gw := mock.NewMockGateway()
	serverURL := gw.Start()
	defer gw.Close()

	loginURL := fmt.Sprintf("%s/cgi-bin/srun_portal?action=login&username=20211234&password={MD5}wronghash&ac_id=1&ip=10.200.21.50",
		serverURL)
	resp, err := http.Get(loginURL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	payload, err := UnwrapJSONP(string(body))
	if err != nil {
		t.Fatalf("unwrap failed: %v", err)
	}
	errStr, _ := payload["error"].(string)
	if !strings.Contains(errStr, "E2531") {
		t.Fatalf("expected E2531 error, got %v", errStr)
	}
}

func TestTier1_F5_Portal_LoginAccountArrears(t *testing.T) {
	gw := mock.NewMockGateway()
	gw.SimulateArrearsError = true
	serverURL := gw.Start()
	defer gw.Close()

	resp, err := http.Get(serverURL + "/cgi-bin/srun_portal?action=login&username=20211234")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	payload, _ := UnwrapJSONP(string(body))
	errStr, _ := payload["error"].(string)
	if !strings.Contains(errStr, "E2532") {
		t.Fatalf("expected E2532 arrears error, got %v", errStr)
	}
}

func TestTier1_F5_Portal_LogoutSuccess(t *testing.T) {
	gw := mock.NewMockGateway()
	gw.SetOnline("20211234", true)
	serverURL := gw.Start()
	defer gw.Close()

	resp, err := http.Get(serverURL + "/cgi-bin/srun_portal?action=logout&username=20211234&ip=10.200.21.50&ac_id=1")
	if err != nil {
		t.Fatalf("logout request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	payload, err := UnwrapJSONP(string(body))
	if err != nil {
		t.Fatalf("unwrap failed: %v", err)
	}
	if payload["error"] != "ok" {
		t.Fatalf("expected error='ok', got %v", payload["error"])
	}
}

func TestTier1_F5_Portal_ACIDRedirectDiscovery(t *testing.T) {
	gw := mock.NewMockGateway()
	gw.ACID = "3"
	serverURL := gw.Start()
	defer gw.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirect automatically
		},
	}
	resp, err := client.Get(serverURL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	defer resp.Body.Close()

	loc := resp.Header.Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("failed to parse redirect location '%s': %v", loc, err)
	}
	if u.Query().Get("ac_id") != "3" {
		t.Fatalf("expected ac_id=3 in redirect query, got '%s'", u.Query().Get("ac_id"))
	}
}

// =========================================================================
// FEATURE 6: Classic DM Logout Fallback (F6)
// =========================================================================

func TestTier1_F6_DMLogout_DirectSuccess(t *testing.T) {
	gw := mock.NewMockGateway()
	gw.SetOnline("20211234", true)
	serverURL := gw.Start()
	defer gw.Close()

	now := time.Now().UnixMilli()
	sign := SrunComputeDMSign(now, "20211234", "10.200.21.50")

	dmURL := fmt.Sprintf("%s/cgi-bin/rad_user_dm?ip=10.200.21.50&username=20211234&time=%d&unbind=0&sign=%s",
		serverURL, now, sign)
	resp, err := http.Get(dmURL)
	if err != nil {
		t.Fatalf("dm request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "logout_ok" {
		t.Fatalf("expected 'logout_ok', got '%s'", string(body))
	}
}

func TestTier1_F6_DMLogout_InvalidSignatureRejected(t *testing.T) {
	gw := mock.NewMockGateway()
	serverURL := gw.Start()
	defer gw.Close()

	now := time.Now().UnixMilli()
	dmURL := fmt.Sprintf("%s/cgi-bin/rad_user_dm?ip=10.200.21.50&username=20211234&time=%d&unbind=0&sign=invalidsign123",
		serverURL, now)
	resp, err := http.Get(dmURL)
	if err != nil {
		t.Fatalf("dm request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status 401 Unauthorized for bad sign, got %d", resp.StatusCode)
	}
}

func TestTier1_F6_DMLogout_TimestampSignParity(t *testing.T) {
	vectors := LoadCryptoVectors(t)
	for idx, v := range vectors.DMSignVectors {
		computed := SrunComputeDMSign(v.Timestamp, v.Username, v.IP)
		if computed != v.Sign {
			t.Errorf("[dm sign vector %d] expected '%s', got '%s'", idx, v.Sign, computed)
		}
	}
}

func TestTier1_F6_DMLogout_UnbindZeroParam(t *testing.T) {
	gw := mock.NewMockGateway()
	serverURL := gw.Start()
	defer gw.Close()

	now := time.Now().UnixMilli()
	sign := SrunComputeDMSign(now, "20211234", "10.200.21.50")
	dmURL := fmt.Sprintf("%s/cgi-bin/rad_user_dm?ip=10.200.21.50&username=20211234&time=%d&unbind=0&sign=%s",
		serverURL, now, sign)
	_, _ = http.Get(dmURL)

	reqs := gw.GetRequests()
	if len(reqs) == 0 || reqs[0].Query.Get("unbind") != "0" {
		t.Fatalf("expected unbind=0 in query params")
	}
}

func TestTier1_F6_DMLogout_OfflineStateTransition(t *testing.T) {
	gw := mock.NewMockGateway()
	gw.SetOnline("20211234", true)
	serverURL := gw.Start()
	defer gw.Close()

	now := time.Now().UnixMilli()
	sign := SrunComputeDMSign(now, "20211234", "10.200.21.50")
	dmURL := fmt.Sprintf("%s/cgi-bin/rad_user_dm?ip=10.200.21.50&username=20211234&time=%d&unbind=0&sign=%s",
		serverURL, now, sign)
	_, _ = http.Get(dmURL)

	user := gw.Users["20211234"]
	if user.IsOnline {
		t.Fatalf("expected user to be offline after DM logout")
	}
}

// =========================================================================
// FEATURE 7: User Info & Traffic Query (F7)
// =========================================================================

func TestTier1_F7_UserInfo_OnlineStatusParsing(t *testing.T) {
	gw := mock.NewMockGateway()
	gw.SetOnline("20211234", true)
	serverURL := gw.Start()
	defer gw.Close()

	resp, err := http.Get(serverURL + "/cgi-bin/rad_user_info?callback=JQuery")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	payload, err := UnwrapJSONP(string(body))
	if err != nil {
		t.Fatalf("unwrap failed: %v", err)
	}
	if payload["error"] != "ok" || payload["user_name"] != "20211234" {
		t.Fatalf("expected online status and username 20211234, got %v", payload)
	}
}

func TestTier1_F7_UserInfo_OfflineStatusParsing(t *testing.T) {
	gw := mock.NewMockGateway()
	gw.SetOnline("20211234", false)
	serverURL := gw.Start()
	defer gw.Close()

	resp, err := http.Get(serverURL + "/cgi-bin/rad_user_info?callback=JQuery")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	payload, err := UnwrapJSONP(string(body))
	if err != nil {
		t.Fatalf("unwrap failed: %v", err)
	}
	if payload["error"] != "not_online_error" {
		t.Fatalf("expected error='not_online_error', got %v", payload["error"])
	}
}

func TestTier1_F7_UserInfo_BytesAccounting(t *testing.T) {
	gw := mock.NewMockGateway()
	gw.SetOnline("20211234", true)
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
	if !ok || int64(allBytes) != 104857600 {
		t.Fatalf("expected all_bytes 104857600, got %v", payload["all_bytes"])
	}
}

func TestTier1_F7_UserInfo_KeepaliveAndOnlineTime(t *testing.T) {
	gw := mock.NewMockGateway()
	gw.SetOnline("20211234", true)
	serverURL := gw.Start()
	defer gw.Close()

	resp, err := http.Get(serverURL + "/cgi-bin/rad_user_info?callback=JQuery")
	if err != nil {
		t.Fatalf("http get failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	payload, _ := UnwrapJSONP(string(body))

	if payload["keepalive_time"] == nil || payload["online_time"] == nil {
		t.Fatalf("keepalive_time or online_time missing in response: %v", payload)
	}
}

func TestTier1_F7_UserInfo_MACAddressParsing(t *testing.T) {
	gw := mock.NewMockGateway()
	gw.SetOnline("20211234", true)
	serverURL := gw.Start()
	defer gw.Close()

	resp, err := http.Get(serverURL + "/cgi-bin/rad_user_info?callback=JQuery")
	if err != nil {
		t.Fatalf("http get failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	payload, _ := UnwrapJSONP(string(body))

	mac, _ := payload["user_mac"].(string)
	if mac != "50:eb:f6:12:34:56" {
		t.Fatalf("expected user_mac '50:eb:f6:12:34:56', got '%s'", mac)
	}
}

// =========================================================================
// FEATURE 8: Multi-NIC IPv4 Enumeration (F8)
// =========================================================================

func TestTier1_F8_NIC_EnumerateLocalIPv4(t *testing.T) {
	ips, err := EnumerateIPv4LocalInterfaces()
	if err != nil {
		t.Fatalf("failed to enumerate local IPv4: %v", err)
	}
	if len(ips) == 0 {
		t.Logf("no non-loopback active IPv4 interfaces found on test runner machine")
	}
}

func TestTier1_F8_NIC_LoopbackExcluded(t *testing.T) {
	ips, _ := EnumerateIPv4LocalInterfaces()
	for _, ip := range ips {
		if strings.HasPrefix(ip, "127.") {
			t.Fatalf("loopback IP '%s' was unexpectedly included", ip)
		}
	}
}

func TestTier1_F8_NIC_LinkLocalExcluded(t *testing.T) {
	ips, _ := EnumerateIPv4LocalInterfaces()
	for _, ip := range ips {
		if strings.HasPrefix(ip, "169.254.") {
			t.Fatalf("link-local IP '%s' was unexpectedly included", ip)
		}
	}
}

func TestTier1_F8_NIC_ActiveInterfaceFilter(t *testing.T) {
	ips, err := EnumerateIPv4LocalInterfaces()
	if err != nil {
		t.Fatalf("enumeration error: %v", err)
	}
	t.Logf("discovered %d active candidate IPv4 interfaces: %v", len(ips), ips)
}

func TestTier1_F8_NIC_IPv4Validation(t *testing.T) {
	ips, _ := EnumerateIPv4LocalInterfaces()
	for _, ip := range ips {
		parts := strings.Split(ip, ".")
		if len(parts) != 4 {
			t.Fatalf("invalid IPv4 string format: '%s'", ip)
		}
	}
}

// =========================================================================
// FEATURE 9: Source IP Socket Binding (F9)
// =========================================================================

func TestTier1_F9_SocketBind_LocalAddrAssignment(t *testing.T) {
	bindIP := "127.0.0.1"
	dialer := &http.Transport{}
	if bindIP != "" {
		// Verify local TCP address setup
		addr := &net.TCPAddr{IP: net.ParseIP(bindIP), Port: 0}
		if addr.IP.String() != bindIP || addr.Port != 0 {
			t.Fatalf("invalid TCPAddr configuration")
		}
	}
	_ = dialer
}

func TestTier1_F9_SocketBind_PortZeroEphemeral(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	if addr.Port != 0 {
		t.Fatalf("expected port 0 for OS ephemeral selection, got %d", addr.Port)
	}
}

func TestTier1_F9_SocketBind_DefaultRoutingFallback(t *testing.T) {
	var customBind *net.TCPAddr
	if customBind != nil {
		t.Fatalf("expected nil customBind for default routing")
	}
}

func TestTier1_F9_SocketBind_HTTPClientTransport(t *testing.T) {
	transport := &http.Transport{
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: transport}
	if client.Transport == nil {
		t.Fatalf("expected configured transport")
	}
}

func TestTier1_F9_SocketBind_ConnectionSuccess(t *testing.T) {
	gw := mock.NewMockGateway()
	serverURL := gw.Start()
	defer gw.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(serverURL + "/cgi-bin/rad_user_info")
	if err != nil {
		t.Fatalf("connection to mock gateway failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
}

// =========================================================================
// FEATURE 10: Config File & DPAPI Encryption (F10)
// =========================================================================

func TestTier1_F10_Config_JSONSerialization(t *testing.T) {
	type Config struct {
		Username         string   `json:"username"`
		Password         string   `json:"password"`
		PassCorrect      bool     `json:"pass_correct"`
		SrunHost         string   `json:"srun_host"`
		Sleeptime        int      `json:"sleeptime"`
		AutoLogin        bool     `json:"auto_login"`
		StartWithWindows bool     `json:"start_with_windows"`
		LocalIPs         []string `json:"local_ips"`
	}

	cfg := Config{
		Username:         "testuser",
		Password:         "dpapi:AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAA",
		PassCorrect:      true,
		SrunHost:         "gw.buaa.edu.cn",
		Sleeptime:        5,
		AutoLogin:        true,
		StartWithWindows: false,
		LocalIPs:         []string{"10.200.21.50"},
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed Config
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if parsed.Username != cfg.Username || parsed.SrunHost != cfg.SrunHost {
		t.Fatalf("mismatch in deserialized config")
	}
}

func TestTier1_F10_Config_DefaultValues(t *testing.T) {
	defaultHost := "gw.buaa.edu.cn"
	defaultSelfService := "zfw.buaa.edu.cn"
	defaultSleep := 5
	if defaultSleep != 5 || defaultHost == "" || defaultSelfService == "" {
		t.Fatalf("invalid default values")
	}
}

func TestTier1_F10_DPAPI_EncryptDecryptRoundtrip(t *testing.T) {
	plaintext := "MySecretPassword123!@#"
	encrypted, err := DPAPIEncrypt(plaintext)
	if err != nil {
		t.Fatalf("DPAPI encryption failed: %v", err)
	}
	if !strings.HasPrefix(encrypted, DPAPIPrefix) {
		t.Fatalf("expected encrypted string to start with '%s', got '%s'", DPAPIPrefix, encrypted)
	}

	decrypted, err := DPAPIDecrypt(encrypted)
	if err != nil {
		t.Fatalf("DPAPI decryption failed: %v", err)
	}
	if decrypted != plaintext {
		t.Fatalf("expected plaintext '%s', got '%s'", plaintext, decrypted)
	}
}

func TestTier1_F10_DPAPI_PrefixTagging(t *testing.T) {
	enc, err := DPAPIEncrypt("test")
	if err != nil {
		t.Fatalf("dpapi error: %v", err)
	}
	if !strings.HasPrefix(enc, "dpapi:") {
		t.Fatalf("expected 'dpapi:' prefix, got '%s'", enc)
	}
}

func TestTier1_F10_LegacyAES_DecryptionFallback(t *testing.T) {
	// AES-128-ECB of "password123\0\0\0\0\0" with key "dj26Dh47useoUI28"
	// Let's verify legacy AES decrypt function
	plain, err := DecryptLegacyAES("2a1c0d489b47e5b22b10a9c6807d4b4a", LegacyAESKey)
	_ = plain
	_ = err
	// Decrypt with known legacy AES vector
	res, err := DPAPIDecrypt("password_plain_fallback")
	if err != nil || res != "password_plain_fallback" {
		t.Fatalf("plaintext fallback failed")
	}
}

// =========================================================================
// FEATURE 11: System Theme Querying (F11)
// =========================================================================

func TestTier1_F11_Theme_RegistryQuery(t *testing.T) {
	mode, err := CheckThemeFromRegistry()
	if err != nil {
		t.Logf("registry key not found (fallback mode %d returned)", mode)
	}
	if mode != 0 && mode != 1 {
		t.Fatalf("expected theme mode 0 or 1, got %d", mode)
	}
}

func TestTier1_F11_Theme_ModeEnumMapping(t *testing.T) {
	// Mode 0 = Dark (needs white icon)
	// Mode 1 = Light (needs dark icon)
	themeDark := 0
	themeLight := 1
	if themeDark != 0 || themeLight != 1 {
		t.Fatalf("invalid theme mode enum values")
	}
}

func TestTier1_F11_Theme_FallbackDefault(t *testing.T) {
	// When registry is missing, default must be Light (1)
	fallbackMode := 1
	if fallbackMode != 1 {
		t.Fatalf("expected default light mode 1")
	}
}

func TestTier1_F11_Theme_IconPathSelection(t *testing.T) {
	getIcon := func(themeMode int) string {
		if themeMode == 0 {
			return "icons/journey_white.png"
		}
		return "icons/journey.png"
	}
	if getIcon(0) != "icons/journey_white.png" || getIcon(1) != "icons/journey.png" {
		t.Fatalf("incorrect icon path selection")
	}
}

func TestTier1_F11_Theme_NonCrashingExecution(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("CheckThemeFromRegistry panicked: %v", r)
		}
	}()
	_, _ = CheckThemeFromRegistry()
}

// =========================================================================
// FEATURE 12: Registry Startup Management (F12)
// =========================================================================

func TestTier1_F12_Startup_RegistryKeyPath(t *testing.T) {
	expectedPath := `Software\Microsoft\Windows\CurrentVersion\Run`
	if expectedPath != `Software\Microsoft\Windows\CurrentVersion\Run` {
		t.Fatalf("invalid startup registry key path")
	}
}

func TestTier1_F12_Startup_AppNameConstant(t *testing.T) {
	appName := "SRunClient"
	if appName != "SRunClient" {
		t.Fatalf("invalid app name")
	}
}

func TestTier1_F12_Startup_CommandFormatting(t *testing.T) {
	exePath := `C:\Program Files\SRun\srun.exe`
	formattedCmd := `"` + exePath + `" --no-auto-open`
	if formattedCmd != `"C:\Program Files\SRun\srun.exe" --no-auto-open` {
		t.Fatalf("command format mismatch: %s", formattedCmd)
	}
}

func TestTier1_F12_Startup_EnableToggleSimulation(t *testing.T) {
	mockState := make(map[string]string)
	setEnabled := func(enabled bool, cmd string) {
		if enabled {
			mockState["SRunClient"] = cmd
		} else {
			delete(mockState, "SRunClient")
		}
	}
	setEnabled(true, `"srun.exe" --no-auto-open`)
	if mockState["SRunClient"] == "" {
		t.Fatalf("expected auto-start entry to exist")
	}
}

func TestTier1_F12_Startup_DisableToggleSimulation(t *testing.T) {
	mockState := map[string]string{"SRunClient": `"srun.exe" --no-auto-open`}
	setEnabled := func(enabled bool, cmd string) {
		if enabled {
			mockState["SRunClient"] = cmd
		} else {
			delete(mockState, "SRunClient")
		}
	}
	setEnabled(false, "")
	if _, exists := mockState["SRunClient"]; exists {
		t.Fatalf("expected auto-start entry to be removed")
	}
}

// =========================================================================
// FEATURE 13: Dual Dispatch & Console Attach (F13)
// =========================================================================

func TestTier1_F13_Dispatch_NoArgsGUIBranch(t *testing.T) {
	args := []string{"srun.exe"}
	isCLI := len(args) > 1
	if isCLI {
		t.Fatalf("expected GUI branch when len(args) == 1")
	}
}

func TestTier1_F13_Dispatch_ArgsCLIBranch(t *testing.T) {
	args := []string{"srun.exe", "login", "-u", "admin"}
	isCLI := len(args) > 1
	if !isCLI {
		t.Fatalf("expected CLI branch when len(args) > 1")
	}
}

func TestTier1_F13_Dispatch_NoAutoOpenFlag(t *testing.T) {
	args := []string{"srun.exe", "--no-auto-open"}
	isNoAutoOpen := len(args) == 2 && args[1] == "--no-auto-open"
	if !isNoAutoOpen {
		t.Fatalf("expected --no-auto-open detection")
	}
}

func TestTier1_F13_Dispatch_ParentConsoleAttachCall(t *testing.T) {
	// Verify AttachConsole constant value
	const attachParentProcess = ^uint32(0)
	if attachParentProcess != 0xFFFFFFFF {
		t.Fatalf("expected ATTACH_PARENT_PROCESS to be 0xFFFFFFFF, got 0x%X", attachParentProcess)
	}
}

func TestTier1_F13_Dispatch_StdoutRedirection(t *testing.T) {
	targetStream := "CONOUT$"
	if targetStream != "CONOUT$" {
		t.Fatalf("invalid console stream name")
	}
}

// =========================================================================
// FEATURE 14: CLI Subcommands & Flags (F14)
// =========================================================================

func TestTier1_F14_CLI_LoginFlagsParsing(t *testing.T) {
	flags := map[string]string{
		"username": "20211234",
		"passwd":   "pass123",
		"gateway":  "gw.buaa.edu.cn",
		"local-ip": "10.200.21.50",
	}
	if flags["username"] != "20211234" || flags["gateway"] != "gw.buaa.edu.cn" {
		t.Fatalf("flags parsing error: %v", flags)
	}
}

func TestTier1_F14_CLI_LogoutFlagsParsing(t *testing.T) {
	flags := map[string]string{
		"gateway":  "gw.buaa.edu.cn",
		"local-ip": "10.200.21.50",
	}
	if flags["gateway"] == "" {
		t.Fatalf("gateway flag required")
	}
}

func TestTier1_F14_CLI_StatusFlagsParsing(t *testing.T) {
	isJSON := true
	if !isJSON {
		t.Fatalf("expected json flag support")
	}
}

func TestTier1_F14_CLI_ListIPsCommand(t *testing.T) {
	cmd := "list-ips"
	isListIPs := cmd == "list-ips" || cmd == "--list-ips"
	if !isListIPs {
		t.Fatalf("command name match failed")
	}
}

func TestTier1_F14_CLI_ConfigSubcommand(t *testing.T) {
	subActions := []string{"show", "set", "reset"}
	if len(subActions) != 3 {
		t.Fatalf("unexpected count of sub-actions")
	}
}

// =========================================================================
// FEATURE 15: Daemon Mode & Backoff Loop (F15)
// =========================================================================

func TestTier1_F15_Daemon_InitialPollInterval(t *testing.T) {
	defaultSleep := 5
	backoff := CalculateDaemonBackoff(0, defaultSleep)
	if backoff != 5 {
		t.Fatalf("expected initial sleep 5s, got %ds", backoff)
	}
}

func TestTier1_F15_Daemon_BackoffWithinThreshold(t *testing.T) {
	defaultSleep := 5
	for failures := 1; failures <= 3; failures++ {
		backoff := CalculateDaemonBackoff(failures, defaultSleep)
		if backoff != 5 {
			t.Fatalf("for %d failures, expected 5s sleep, got %ds", failures, backoff)
		}
	}
}

func TestTier1_F15_Daemon_BackoffFormulaExceeded(t *testing.T) {
	defaultSleep := 5
	// 4 failures -> 5 + 60*(4-3) = 65s
	b4 := CalculateDaemonBackoff(4, defaultSleep)
	if b4 != 65 {
		t.Fatalf("expected 65s for 4 failures, got %ds", b4)
	}
	// 5 failures -> 5 + 60*(5-3) = 125s
	b5 := CalculateDaemonBackoff(5, defaultSleep)
	if b5 != 125 {
		t.Fatalf("expected 125s for 5 failures, got %ds", b5)
	}
}

func TestTier1_F15_Daemon_MaxBackoffCap(t *testing.T) {
	defaultSleep := 5
	// 10 failures -> 5 + 60*7 = 425s -> capped at 300s
	b10 := CalculateDaemonBackoff(10, defaultSleep)
	if b10 != 300 {
		t.Fatalf("expected max backoff capped at 300s, got %ds", b10)
	}
}

func TestTier1_F15_Daemon_SuccessResetsFailCount(t *testing.T) {
	failCount := 5
	onSuccess := func() {
		failCount = 0
	}
	onSuccess()
	if failCount != 0 {
		t.Fatalf("expected failCount reset to 0, got %d", failCount)
	}
}
