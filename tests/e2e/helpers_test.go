package e2e_test

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	SrunBase64Alpha = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
	DPAPIPrefix     = "dpapi:"
	LegacyAESKey    = "dj26Dh47useoUI28"
)

// CryptoVectorData models the schema of crypto_vectors.json
type CryptoVectorData struct {
	SencodeVectors []struct {
		Input       string   `json:"input"`
		AppendLen   bool     `json:"append_len"`
		OutputWords []uint32 `json:"output_words"`
	} `json:"sencode_vectors"`
	CustomBase64Vectors []struct {
		Input  string `json:"input"`
		Output string `json:"output"`
	} `json:"custom_base64_vectors"`
	MD5HMACVectors []struct {
		Password string `json:"password"`
		Token    string `json:"token"`
		Output   string `json:"output"`
	} `json:"md5_hmac_vectors"`
	XEncodeVectors []struct {
		Msg             string `json:"msg"`
		Key             string `json:"key"`
		OutputBytes     []byte `json:"output_bytes"`
		OutputHex       string `json:"output_hex"`
		OutputCustomB64 string `json:"output_custom_b64"`
	} `json:"xencode_vectors"`
	SHA1Vectors []struct {
		Input  string `json:"input"`
		Output string `json:"output"`
	} `json:"sha1_vectors"`
	DMSignVectors []struct {
		Username  string `json:"username"`
		IP        string `json:"ip"`
		Timestamp int64  `json:"timestamp"`
		SignStr   string `json:"sign_str"`
		Sign      string `json:"sign"`
	} `json:"dm_sign_vectors"`
	FullLoginPackets []struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		IP         string `json:"ip"`
		ACID       string `json:"acid"`
		Token      string `json:"token"`
		InfoJSON   string `json:"info_json"`
		XEncodeHex string `json:"xencode_hex"`
		InfoParam  string `json:"info_param"`
		HMD5       string `json:"hmd5"`
		Chkstr     string `json:"chkstr"`
		Chksum     string `json:"chksum"`
	} `json:"full_login_packets"`
}

// LoadCryptoVectors reads and parses tests/vectors/crypto_vectors.json
func LoadCryptoVectors(t *testing.T) *CryptoVectorData {
	t.Helper()
	possiblePaths := []string{
		"../vectors/crypto_vectors.json",
		"tests/vectors/crypto_vectors.json",
		"../../tests/vectors/crypto_vectors.json",
		"e:/project/srun-go/tests/vectors/crypto_vectors.json",
	}

	var data []byte
	var err error
	for _, p := range possiblePaths {
		data, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("failed to locate and read crypto_vectors.json: %v", err)
	}

	var vectors CryptoVectorData
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("failed to unmarshal crypto_vectors.json: %v", err)
	}
	return &vectors
}

// Pure Go reference implementation of Srun sencode
func SrunSencode(msg string, appendLen bool) []uint32 {
	l := len(msg)
	b := []byte(msg)
	words := make([]uint32, 0, (l+3)/4+1)

	for i := 0; i < l; i += 4 {
		var w uint32
		w |= uint32(b[i])
		if i+1 < l {
			w |= uint32(b[i+1]) << 8
		}
		if i+2 < l {
			w |= uint32(b[i+2]) << 16
		}
		if i+3 < l {
			w |= uint32(b[i+3]) << 24
		}
		words = append(words, w)
	}

	if appendLen {
		words = append(words, uint32(l))
	}
	return words
}

// Pure Go reference implementation of Srun lencode
func SrunLencode(words []uint32, checkLen bool) []byte {
	l := len(words)
	if l == 0 {
		return []byte{}
	}
	ll := (l - 1) << 2
	if checkLen {
		m := int(words[l-1])
		if m < ll-3 || m > ll {
			return nil
		}
		ll = m
	}

	buf := make([]byte, l*4)
	for i := 0; i < l; i++ {
		w := words[i]
		buf[i*4] = byte(w & 0xFF)
		buf[i*4+1] = byte((w >> 8) & 0xFF)
		buf[i*4+2] = byte((w >> 16) & 0xFF)
		buf[i*4+3] = byte((w >> 24) & 0xFF)
	}

	if checkLen {
		return buf[:ll]
	}
	return buf
}

// Pure Go reference implementation of Srun XEncode (XXTEA variant)
func SrunXEncode(msg string, key string) []byte {
	if msg == "" {
		return []byte{}
	}
	pwd := SrunSencode(msg, true)
	pwdk := SrunSencode(key, false)
	for len(pwdk) < 4 {
		pwdk = append(pwdk, 0)
	}

	n := len(pwd) - 1
	z := pwd[n]
	c := uint32(0x9E3779B9)
	q := uint32(math.Floor(float64(6 + 52/(n+1))))
	d := uint32(0)

	for q > 0 {
		d += c
		e := (d >> 2) & 3
		for p := 0; p < n; p++ {
			y := pwd[p+1]
			m := (z >> 5) ^ (y << 2)
			m += ((y >> 3) ^ (z << 4)) ^ (d ^ y)
			m += pwdk[(uint32(p)&3)^e] ^ z
			pwd[p] += m
			z = pwd[p]
		}
		y := pwd[0]
		m := (z >> 5) ^ (y << 2)
		m += ((y >> 3) ^ (z << 4)) ^ (d ^ y)
		m += pwdk[(uint32(n)&3)^e] ^ z
		pwd[n] += m
		z = pwd[n]
		q--
	}

	return SrunLencode(pwd, false)
}

// Pure Go reference implementation of Srun Custom Base64
func SrunCustomBase64(input []byte) string {
	if len(input) == 0 {
		return ""
	}
	l := len(input)
	pad := l % 3
	padded := make([]byte, l)
	copy(padded, input)
	if pad != 0 {
		extra := 3 - pad
		padded = append(padded, make([]byte, extra)...)
	}

	var sb strings.Builder
	for i := 0; i < len(padded); i += 3 {
		a := (uint32(padded[i]) << 16) | (uint32(padded[i+1]) << 8) | uint32(padded[i+2])
		sb.WriteByte(SrunBase64Alpha[(a>>18)&63])
		sb.WriteByte(SrunBase64Alpha[(a>>12)&63])
		sb.WriteByte(SrunBase64Alpha[(a>>6)&63])
		sb.WriteByte(SrunBase64Alpha[a&63])
	}

	res := []byte(sb.String())
	if pad == 1 {
		res[len(res)-1] = '='
		res[len(res)-2] = '='
	} else if pad == 2 {
		res[len(res)-1] = '='
	}
	return string(res)
}

// Pure Go reference implementation of Srun MD5-HMAC
func SrunMD5HMAC(password, token string) string {
	h := hmac.New(md5.New, []byte(token))
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

// Pure Go reference implementation of Srun SHA1
func SrunSHA1(value string) string {
	h := sha1.Sum([]byte(value))
	return hex.EncodeToString(h[:])
}

// SrunComputeChksum calculates the login verification SHA1
func SrunComputeChksum(username, token, hmd5, ip, info, acid, n, type_ string) string {
	var sb strings.Builder
	sb.WriteString(token)
	sb.WriteString(username)
	sb.WriteString(token)
	sb.WriteString(hmd5)
	sb.WriteString(token)
	sb.WriteString(acid)
	sb.WriteString(token)
	sb.WriteString(ip)
	sb.WriteString(token)
	sb.WriteString(n)
	sb.WriteString(token)
	sb.WriteString(type_)
	sb.WriteString(token)
	sb.WriteString(info)
	return SrunSHA1(sb.String())
}

// SrunComputeDMSign calculates the DM fallback logout SHA1 signature
func SrunComputeDMSign(t int64, username, ip string) string {
	tStr := fmt.Sprintf("%d", t)
	raw := tStr + username + ip + "0" + tStr
	return SrunSHA1(raw)
}

// UnwrapJSONP extracts JSON payload from JSONP wrapper
func UnwrapJSONP(raw string) (map[string]any, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return nil, fmt.Errorf("empty response")
	}
	start := strings.Index(text, "(")
	end := strings.LastIndex(text, ")")
	if start != -1 && end > start {
		text = strings.TrimSpace(text[start+1 : end])
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		return nil, fmt.Errorf("invalid json payload: %w", err)
	}
	return out, nil
}

// Windows DPAPI Wrappers
var (
	dllCrypt32             = windows.NewLazySystemDLL("crypt32.dll")
	procCryptProtectData   = dllCrypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = dllCrypt32.NewProc("CryptUnprotectData")
)

const cryptProtectUIForbidden = 0x1

// DPAPIEncrypt encrypts plaintext with current Windows user DPAPI
func DPAPIEncrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	data := []byte(plaintext)
	var inBlob windows.DataBlob
	inBlob.Size = uint32(len(data))
	inBlob.Data = &data[0]

	var outBlob windows.DataBlob
	r, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, 0, 0, 0,
		uintptr(cryptProtectUIForbidden),
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if r == 0 {
		return "", fmt.Errorf("CryptProtectData failed: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.Data)))

	cipherBytes := unsafe.Slice(outBlob.Data, outBlob.Size)
	return DPAPIPrefix + base64.StdEncoding.EncodeToString(cipherBytes), nil
}

// DPAPIDecrypt decrypts ciphertext using DPAPI, legacy AES, or plaintext
func DPAPIDecrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	if strings.HasPrefix(ciphertext, DPAPIPrefix) {
		rawB64 := strings.TrimPrefix(ciphertext, DPAPIPrefix)
		cipherBytes, err := base64.StdEncoding.DecodeString(rawB64)
		if err != nil {
			return "", fmt.Errorf("invalid base64: %w", err)
		}
		var inBlob windows.DataBlob
		inBlob.Size = uint32(len(cipherBytes))
		inBlob.Data = &cipherBytes[0]

		var outBlob windows.DataBlob
		r, _, err := procCryptUnprotectData.Call(
			uintptr(unsafe.Pointer(&inBlob)),
			0, 0, 0, 0,
			uintptr(cryptProtectUIForbidden),
			uintptr(unsafe.Pointer(&outBlob)),
		)
		if r == 0 {
			return "", fmt.Errorf("CryptUnprotectData failed: %w", err)
		}
		defer windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.Data)))

		plainBytes := unsafe.Slice(outBlob.Data, outBlob.Size)
		return string(plainBytes), nil
	}

	// Legacy AES fallback
	if len(ciphertext) >= 32 {
		if plain, err := DecryptLegacyAES(ciphertext, LegacyAESKey); err == nil {
			return plain, nil
		}
	}

	return ciphertext, nil
}

// DecryptLegacyAES decrypts AES-128-ECB null-padded hex strings from Python
func DecryptLegacyAES(hexCipher string, key string) (string, error) {
	cipherBytes, err := hex.DecodeString(hexCipher)
	if err != nil {
		return "", fmt.Errorf("invalid hex string: %w", err)
	}
	if len(cipherBytes)%16 != 0 {
		return "", fmt.Errorf("invalid ciphertext block size")
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", fmt.Errorf("invalid aes key: %w", err)
	}
	plain := make([]byte, len(cipherBytes))
	for i := 0; i < len(cipherBytes); i += 16 {
		block.Decrypt(plain[i:i+16], cipherBytes[i:i+16])
	}
	// Trim null bytes
	trimmed := strings.TrimRight(string(plain), "\x00")
	return trimmed, nil
}

// EnumerateIPv4LocalInterfaces returns list of active IPv4 addresses
func EnumerateIPv4LocalInterfaces() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var ips []string
	seen := make(map[string]bool)

	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.To4() == nil {
				continue
			}
			ipStr := ip.To4().String()
			if !seen[ipStr] && !strings.HasPrefix(ipStr, "169.254.") {
				seen[ipStr] = true
				ips = append(ips, ipStr)
			}
		}
	}
	return ips, nil
}

// CalculateDaemonBackoff computes backoff sleep duration in seconds
func CalculateDaemonBackoff(consecutiveFailures int, defaultSleep int) int {
	if consecutiveFailures <= 3 {
		return defaultSleep
	}
	backoff := defaultSleep + 60*(consecutiveFailures-3)
	if backoff > 300 {
		return 300
	}
	return backoff
}

// CheckThemeFromRegistry reads HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize
func CheckThemeFromRegistry() (int, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, registry.QUERY_VALUE)
	if err != nil {
		return 1, err // default light mode
	}
	defer k.Close()

	val, _, err := k.GetIntegerValue("SystemUsesLightTheme")
	if err != nil {
		return 1, err
	}
	return int(val), nil
}
