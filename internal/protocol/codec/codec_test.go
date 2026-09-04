package codec

import (
	"testing"
)

func TestXEncode_Basic(t *testing.T) {
	msg := `{"username":"20210001","password":"password123","ip":"10.0.0.1","acid":"1","enc_ver":"srun_bx1"}`
	key := "4d1d6a789c1b4e2f8a3c5d6e7f8a9b0c"

	encoded := XEncode(msg, key)
	if len(encoded) == 0 {
		t.Fatalf("expected non-empty XEncode result")
	}

	b64 := Base64Encode(encoded)
	if len(b64) == 0 {
		t.Fatalf("expected non-empty Base64Encode result")
	}
}

func TestBase64_AlphabetParity(t *testing.T) {
	input := "Hello SRun Go Protocol Engine"
	encoded := Base64Encode(input)
	if len(encoded) == 0 {
		t.Fatalf("base64 encoding failed")
	}

	for _, r := range encoded {
		if r == '=' {
			continue
		}
		found := false
		for _, valid := range SRunBase64Alphabet {
			if r == valid {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("character %c not in SRun custom base64 alphabet", r)
		}
	}
}

func TestCrypto_HmacAndChecksum(t *testing.T) {
	token := "4d1d6a789c1b4e2f"
	pass := "mySecretPass"
	hmacHex := HmacMd5Hex(token, pass)
	if len(hmacHex) != 32 {
		t.Fatalf("expected 32-hex MD5 HMAC, got %s", hmacHex)
	}

	checksum := GenerateChecksum(token, "user1", hmacHex, "1", "10.0.0.1", "200", "1", "{SRBX1}abc")
	if len(checksum) != 40 {
		t.Fatalf("expected 40-hex SHA1 Checksum, got %s", checksum)
	}

	dmSign := DMSign("user1", "10.0.0.1", "1600000000000")
	if len(dmSign) != 40 {
		t.Fatalf("expected 40-hex DM sign, got %s", dmSign)
	}
}

type SrunTestPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
	IP       string `json:"ip"`
	ACID     string `json:"acid"`
	EncVer   string `json:"enc_ver"`
}

func TestFullLoginPackets_VectorParity(t *testing.T) {
	// Vector 1: student_abc
	payload1 := SrunTestPayload{
		Username: "student_abc",
		Password: "MyP@ssw0rd!#$",
		IP:       "192.168.10.25",
		ACID:     "2",
		EncVer:   "srun_bx1",
	}
	token1 := "11223344556677889900aabbccddeeff"
	infoParam1, err := GenerateInfo(payload1, token1)
	if err != nil {
		t.Fatalf("GenerateInfo failed: %v", err)
	}
	expectedInfo1 := "{SRBX1}iB5Gf/hgw5h6Rp/JuUTHkd9mbOAGlUJTU8m/vVXVGEemQBURd3s1u9hVsPX3PPSuIo4PlZIbHJZfuf90Ugmp69ZiFcJKFNAYmAm0s5J4gHaX8m9ol3kOqYHs6IOS9SJ74WFQR4s/PW0zhY+B6QLNj+=="
	if infoParam1 != expectedInfo1 {
		t.Errorf("info_param mismatch:\ngot:  %s\nwant: %s", infoParam1, expectedInfo1)
	}

	hmd5_1 := HmacMd5Hex(token1, payload1.Password)
	if hmd5_1 != "f0532f44eebcee203c78e78733519960" {
		t.Errorf("hmd5 mismatch: got %s", hmd5_1)
	}

	chksum1 := GenerateChecksum(token1, payload1.Username, hmd5_1, payload1.ACID, payload1.IP, "200", "1", infoParam1)
	if chksum1 != "b6bc5ae4cfde588587f7ce7fdc61a92643752059" {
		t.Errorf("chksum mismatch: got %s, want b6bc5ae4cfde588587f7ce7fdc61a92643752059", chksum1)
	}

	// Vector 2: buaa_user_001
	payload2 := SrunTestPayload{
		Username: "buaa_user_001",
		Password: "ComplexPass123!@#",
		IP:       "10.200.1.100",
		ACID:     "1",
		EncVer:   "srun_bx1",
	}
	token2 := "abcdef0123456789abcdef0123456789"
	infoParam2, err := GenerateInfo(payload2, token2)
	if err != nil {
		t.Fatalf("GenerateInfo failed: %v", err)
	}
	expectedInfo2 := "{SRBX1}dG6IoHnUyFQviiWlGYEnutVCcIOuVcszeVugZ9MAYCBGhu+4AwukkY9ger36H4vraYy+RqnbswDuN6T16UdFABvclIvMtkLci3lfYwGtrIJbqtv31Gmo7QcjxtMHqeyHewgQthkuvevrWYuLFFsbKEFp4f9="
	if infoParam2 != expectedInfo2 {
		t.Errorf("info_param mismatch:\ngot:  %s\nwant: %s", infoParam2, expectedInfo2)
	}

	hmd5_2 := HmacMd5Hex(token2, payload2.Password)
	chksum2 := GenerateChecksum(token2, payload2.Username, hmd5_2, payload2.ACID, payload2.IP, "200", "1", infoParam2)
	if chksum2 != "37295a97a98a17032b211e39dedec350090498f9" {
		t.Errorf("chksum mismatch: got %s, want 37295a97a98a17032b211e39dedec350090498f9", chksum2)
	}

	// Vector 3: guest_account
	payload3 := SrunTestPayload{
		Username: "guest_account",
		Password: "guest_password_test",
		IP:       "172.18.3.4",
		ACID:     "5",
		EncVer:   "srun_bx1",
	}
	token3 := "99887766554433221100ffeeddccbbaa"
	infoParam3, err := GenerateInfo(payload3, token3)
	if err != nil {
		t.Fatalf("GenerateInfo failed: %v", err)
	}
	expectedInfo3 := "{SRBX1}P77zhY/gSj4eP5BDXB/FEnNuGfmvK8Ghbd5sqJUJtqG9m6F8XUimr36VEV6SKByBm28h+UWhoVrFok3yx9a+sklr++l7gSZP/53aCTK5KJjf2DZIrLZ55jKt9/PtD+BiuVdVo9+5RmBliwepZkz26G6zhlY="
	if infoParam3 != expectedInfo3 {
		t.Errorf("info_param mismatch:\ngot:  %s\nwant: %s", infoParam3, expectedInfo3)
	}

	hmd5_3 := HmacMd5Hex(token3, payload3.Password)
	chksum3 := GenerateChecksum(token3, payload3.Username, hmd5_3, payload3.ACID, payload3.IP, "200", "1", infoParam3)
	if chksum3 != "e5f44d61223508ed8243f52ce519a96f3211bdab" {
		t.Errorf("chksum mismatch: got %s, want e5f44d61223508ed8243f52ce519a96f3211bdab", chksum3)
	}
}
