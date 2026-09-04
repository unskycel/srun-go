package codec

import (
	"bytes"
	"math"
)

const (
	XEncodeDelta = 0x9E3779B9
)

// Lencode converts a string into an array of 32-bit integers.
// If isKey is true, it forces length 4 (required for XEncode 128-bit key).
func Lencode(msg string, isKey bool) []int64 {
	n := len(msg)
	pwd := make([]int64, int(math.Ceil(float64(n)/4.0)))
	for i := 0; i < n; i++ {
		idx := i >> 2
		pwd[idx] |= int64(msg[i]) << ((uint(i) & 3) << 3)
	}
	if isKey {
		if len(pwd) > 4 {
			pwd = pwd[:4]
		}
		for len(pwd) < 4 {
			pwd = append(pwd, 0)
		}
		return pwd
	}
	pwd = append(pwd, int64(n))
	return pwd
}

// Sencode performs the multi-round TEA-variant Feistel cipher core.
func Sencode(msg string, key string) []int64 {
	if len(msg) == 0 {
		return []int64{}
	}

	v := Lencode(msg, false)
	k := Lencode(key, true)

	n := int64(len(v) - 1)
	z := v[n]
	var y int64
	var d int64 = 0
	q := int64(math.Floor(6.0 + 52.0/float64(n+1)))

	for q > 0 {
		d = (d + XEncodeDelta) & 0xFFFFFFFF
		e := (d >> 2) & 3
		var p int64
		for p = 0; p < n; p++ {
			y = v[p+1]
			m := (z >> 5) ^ (y << 2)
			m += ((y >> 3) ^ (z << 4)) ^ (d ^ y)
			m += k[(p&3)^e] ^ z
			v[p] = (v[p] + m) & 0xFFFFFFFF
			z = v[p]
		}
		y = v[0]
		m := (z >> 5) ^ (y << 2)
		m += ((y >> 3) ^ (z << 4)) ^ (d ^ y)
		m += k[(n&3)^e] ^ z
		v[n] = (v[n] + m) & 0xFFFFFFFF
		z = v[n]
		q--
	}

	return v
}

// XEncode converts the sencoded integer vector into byte stream.
func XEncode(msg string, key string) string {
	if len(msg) == 0 {
		return ""
	}

	v := Sencode(msg, key)
	var buf bytes.Buffer
	for _, val := range v {
		buf.WriteByte(byte(val & 0xFF))
		buf.WriteByte(byte((val >> 8) & 0xFF))
		buf.WriteByte(byte((val >> 16) & 0xFF))
		buf.WriteByte(byte((val >> 24) & 0xFF))
	}
	return buf.String()
}
