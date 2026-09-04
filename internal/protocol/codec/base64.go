package codec

import (
	"bytes"
	"fmt"
	"strings"
)

const (
	SRunBase64Alphabet = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
	SRunBase64Pad      = "="
)

// Base64Encode encodes binary string data using SRun custom base64 alphabet.
func Base64Encode(data string) string {
	if len(data) == 0 {
		return ""
	}

	var buf bytes.Buffer
	src := []byte(data)
	n := len(src)

	for i := 0; i < n; i += 3 {
		b0 := src[i]
		var b1, b2 byte
		if i+1 < n {
			b1 = src[i+1]
		}
		if i+2 < n {
			b2 = src[i+2]
		}

		c0 := b0 >> 2
		c1 := ((b0 & 3) << 4) | (b1 >> 4)
		c2 := ((b1 & 15) << 2) | (b2 >> 6)
		c3 := b2 & 63

		buf.WriteByte(SRunBase64Alphabet[c0])
		buf.WriteByte(SRunBase64Alphabet[c1])

		if i+1 < n {
			buf.WriteByte(SRunBase64Alphabet[c2])
		} else {
			buf.WriteString(SRunBase64Pad)
		}

		if i+2 < n {
			buf.WriteByte(SRunBase64Alphabet[c3])
		} else {
			buf.WriteString(SRunBase64Pad)
		}
	}

	return buf.String()
}

// Base64Decode decodes a custom base64 encoded string back to binary.
func Base64Decode(data string) (string, error) {
	clean := strings.TrimRight(data, "=")
	if len(clean) == 0 {
		return "", nil
	}

	charMap := make(map[rune]byte, len(SRunBase64Alphabet))
	for i, r := range SRunBase64Alphabet {
		charMap[r] = byte(i)
	}

	var buf bytes.Buffer
	runes := []rune(clean)
	n := len(runes)

	for i := 0; i < n; i += 4 {
		var c [4]byte
		for j := 0; j < 4; j++ {
			if i+j < n {
				val, ok := charMap[runes[i+j]]
				if !ok {
					return "", fmt.Errorf("invalid character %c in base64 string", runes[i+j])
				}
				c[j] = val
			}
		}

		b0 := (c[0] << 2) | (c[1] >> 4)
		buf.WriteByte(b0)

		if i+2 <= n {
			if i+2 == n && (len(data)%4 == 2 || (len(data)%4 == 0 && strings.HasSuffix(data, "=="))) {
				break
			}
			b1 := ((c[1] & 15) << 4) | (c[2] >> 2)
			buf.WriteByte(b1)
		}

		if i+3 <= n {
			if i+3 == n && (len(data)%4 == 3 || (len(data)%4 == 0 && strings.HasSuffix(data, "="))) {
				break
			}
			b2 := ((c[2] & 3) << 6) | c[3]
			buf.WriteByte(b2)
		}
	}

	return buf.String(), nil
}
