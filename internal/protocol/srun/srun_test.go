package srun

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExtractJSONP(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{`jQuery12345({"res":"ok","challenge":"abc"});`, `{"res":"ok","challenge":"abc"}`},
		{`{"res":"ok","challenge":"abc"}`, `{"res":"ok","challenge":"abc"}`},
		{`  jsonp_cb( {"ecode":0} ) ; `, `{"ecode":0}`},
	}

	for _, c := range cases {
		out, err := ExtractJSONP(c.input)
		if err != nil {
			t.Fatalf("ExtractJSONP failed for %s: %v", c.input, err)
		}
		if string(out) != c.expected {
			t.Fatalf("expected '%s', got '%s'", c.expected, string(out))
		}
	}
}

func TestSRunClient_MockFlow(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch path {
		case "/cgi-bin/get_challenge":
			w.Write([]byte(`jQuery123({"challenge":"test_token_123","client_ip":"10.10.10.10","res":"ok"});`))
		case "/cgi-bin/srun_portal":
			w.Write([]byte(`jQuery123({"error":"ok","res":"ok","client_ip":"10.10.10.10","suc_msg":"login_ok"});`))
		case "/cgi-bin/rad_user_info":
			w.Write([]byte(`jQuery123({"error":"ok","client_ip":"10.10.10.10","user_name":"testuser","user_balance":25.5,"sum_bytes":1048576});`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	client := NewClient(host, "1", "")

	ctx := context.Background()

	// 1. Get Challenge
	chal, err := client.GetChallenge(ctx, "testuser", "")
	if err != nil || chal.Challenge != "test_token_123" {
		t.Fatalf("GetChallenge failed: %v, chal=%+v", err, chal)
	}

	// 2. Login
	loginRes, err := client.Login(ctx, "testuser", "testpass")
	if err != nil || loginRes.Error != "ok" {
		t.Fatalf("Login failed: %v, loginRes=%+v", err, loginRes)
	}

	// 3. User Info
	info, err := client.GetUserInfo(ctx)
	if err != nil || !info.IsOnline || info.UserName != "testuser" || info.UserBalance != 25.5 {
		t.Fatalf("GetUserInfo failed: %v, info=%+v", err, info)
	}
}
