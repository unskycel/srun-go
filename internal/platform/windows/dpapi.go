package windows

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	dllCrypt32            = windows.NewLazySystemDLL("crypt32.dll")
	procCryptProtectData   = dllCrypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = dllCrypt32.NewProc("CryptUnprotectData")
)

const (
	DPAPIPrefix  = "DPAPI:"
	LegacyPrefix = "ENC:"
)

// DPAPIEncrypt encrypts a plaintext string using Windows DPAPI (tied to current Windows user).
func DPAPIEncrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	dataBytes := []byte(plaintext)
	var inBlob windows.DataBlob
	inBlob.Size = uint32(len(dataBytes))
	inBlob.Data = &dataBytes[0]

	var outBlob windows.DataBlob

	r, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if r == 0 {
		return "", fmt.Errorf("CryptProtectData failed: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.Data)))

	encryptedBytes := unsafe.Slice(outBlob.Data, outBlob.Size)
	return DPAPIPrefix + hex.EncodeToString(encryptedBytes), nil
}

// DPAPIDecrypt decrypts a DPAPI-encrypted hex string.
func DPAPIDecrypt(cipherHex string) (string, error) {
	cleanHex := strings.TrimPrefix(cipherHex, DPAPIPrefix)
	if cleanHex == "" {
		return "", nil
	}

	encBytes, err := hex.DecodeString(cleanHex)
	if err != nil {
		return "", fmt.Errorf("invalid hex in DPAPI ciphertext: %w", err)
	}

	var inBlob windows.DataBlob
	inBlob.Size = uint32(len(encBytes))
	inBlob.Data = &encBytes[0]

	var outBlob windows.DataBlob

	r, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if r == 0 {
		return "", fmt.Errorf("CryptUnprotectData failed: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.Data)))

	decryptedBytes := unsafe.Slice(outBlob.Data, outBlob.Size)
	return string(decryptedBytes), nil
}

// DecryptPasswordWithFallback decrypts either DPAPI, Legacy AES, or returns plaintext as-is.
func DecryptPasswordWithFallback(encrypted string, fallbackKey []byte) (string, error) {
	if encrypted == "" {
		return "", nil
	}

	if strings.HasPrefix(encrypted, DPAPIPrefix) {
		return DPAPIDecrypt(encrypted)
	}

	if strings.HasPrefix(encrypted, LegacyPrefix) {
		cleanHex := strings.TrimPrefix(encrypted, LegacyPrefix)
		raw, err := hex.DecodeString(cleanHex)
		if err != nil {
			return "", err
		}
		return DecryptLegacyAES(raw, fallbackKey)
	}

	// Try DPAPI directly if it might be raw hex
	dec, err := DPAPIDecrypt(encrypted)
	if err == nil && dec != "" {
		return dec, nil
	}

	// Unencrypted plaintext
	return encrypted, nil
}

// DecryptLegacyAES decrypts AES-CBC with PKCS7 padding.
func DecryptLegacyAES(ciphertext []byte, key []byte) (string, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		key = []byte("1234567890123456")
	}
	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := ciphertext[:aes.BlockSize]
	data := ciphertext[aes.BlockSize:]

	if len(data)%aes.BlockSize != 0 {
		return "", errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)

	// Unpad PKCS7
	length := len(data)
	if length == 0 {
		return "", errors.New("empty decrypted data")
	}
	unpadding := int(data[length-1])
	if unpadding > length || unpadding == 0 {
		return "", errors.New("invalid padding")
	}
	for i := length - unpadding; i < length; i++ {
		if int(data[i]) != unpadding {
			return "", errors.New("invalid padding bytes")
		}
	}

	return string(data[:(length - unpadding)]), nil
}

func init() {
	// Silence unused variable warning
	_ = syscall.Errno(0)
	_ = io.EOF
	_ = bytes.Buffer{}
	_ = rand.Reader
}
