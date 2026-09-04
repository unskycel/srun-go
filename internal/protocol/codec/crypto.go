package codec

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// HmacMd5Hex calculates MD5-HMAC: hmac.new(token, password, md5).hexdigest()
func HmacMd5Hex(token, password string) string {
	h := hmac.New(md5.New, []byte(token))
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

// Sha1Hex calculates standard SHA1 hash formatted as lowercase hex string.
func Sha1Hex(data string) string {
	h := sha1.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// GenerateInfo serializes user parameters and encrypts it with XEncode and custom Base64:
// Returns "{SRBX1}" + Base64(XEncode(JSON(infoObj), token))
func GenerateInfo(infoObj any, token string) (string, error) {
	jsonBytes, err := json.Marshal(infoObj)
	if err != nil {
		return "", fmt.Errorf("failed to marshal info payload: %w", err)
	}

	xencoded := XEncode(string(jsonBytes), token)
	b64 := Base64Encode(xencoded)
	return "{SRBX1}" + b64, nil
}

// GenerateChecksum calculates the SRun SHA1 checksum for authentication verification:
// SHA1(token + username + token + hmac + token + acid + token + ip + token + n + token + type + token + info)
func GenerateChecksum(token, username, md5Hmac, acid, ip, n, typeStr, infoParam string) string {
	var sb strings.Builder
	sb.WriteString(token)
	sb.WriteString(username)
	sb.WriteString(token)
	sb.WriteString(md5Hmac)
	sb.WriteString(token)
	sb.WriteString(acid)
	sb.WriteString(token)
	sb.WriteString(ip)
	sb.WriteString(token)
	sb.WriteString(n)
	sb.WriteString(token)
	sb.WriteString(typeStr)
	sb.WriteString(token)
	sb.WriteString(infoParam)

	return Sha1Hex(sb.String())
}

// DMSign calculates the SHA1 signature for classic DM logout fallback (`rad_user_dm`):
// SHA1(timeStr + username + ip + "0" + timeStr)
func DMSign(username, ip, timeStr string) string {
	signStr := timeStr + username + ip + "0" + timeStr
	return Sha1Hex(signStr)
}
