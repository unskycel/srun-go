package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"srun/internal/domain/event"
	"srun/internal/domain/model"
)

func TestService_ConfigAndAuthIntegration(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	bus := event.NewBus()
	cfgSvc := NewConfigService(bus)
	netSvc := NewNetworkService()
	authSvc := NewAuthService(cfgSvc, netSvc, bus)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cgi-bin/get_challenge":
			w.Write([]byte(`jQuery1({"challenge":"test_chal","client_ip":"10.0.0.1","res":"ok"});`))
		case "/cgi-bin/srun_portal":
			w.Write([]byte(`jQuery1({"error":"ok","res":"ok","client_ip":"10.0.0.1","suc_msg":"login_ok"});`))
		case "/cgi-bin/rad_user_info":
			w.Write([]byte(`jQuery1({"error":"ok","client_ip":"10.0.0.1","user_name":"testuser","user_balance":50.0,"sum_bytes":2048});`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")

	_ = cfgSvc.Update(func(c *model.Config) {
		c.SrunHost = host
		c.Username = "testuser"
		_ = c.SetPlainPassword("testpwd")
	})

	ctx := context.Background()

	// Test Login
	res, err := authSvc.Login(ctx, "")
	if err != nil || res.Error != "ok" {
		t.Fatalf("Login failed: %v", err)
	}

	if authSvc.GetState() != model.StateOnline {
		t.Fatalf("expected state Online, got %s", authSvc.GetState())
	}

	// Test GetUserInfo
	info, err := authSvc.GetUserInfo(ctx, "")
	if err != nil || !info.IsOnline || info.UserBalance != 50.0 {
		t.Fatalf("GetUserInfo failed: %v, info=%+v", err, info)
	}

	// Test DaemonService
	daemonSvc := NewDaemonService(cfgSvc, authSvc)
	daemonCtx, daemonCancel := context.WithCancel(context.Background())
	daemonSvc.Start(daemonCtx)
	time.Sleep(100 * time.Millisecond)
	daemonCancel()
	daemonSvc.Stop()
}

func TestAuthService_GenerateSSOURL_DirectMode(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	bus := event.NewBus()
	cfgSvc := NewConfigService(bus)
	netSvc := NewNetworkService()
	authSvc := NewAuthService(cfgSvc, netSvc, bus)
	ctx := context.Background()

	// 1. Empty self service
	_, err := authSvc.GenerateSSOURL(ctx, "")
	if err == nil {
		t.Fatalf("expected error for empty self service")
	}

	// 2. Full HTTPS with custom port and path
	_ = cfgSvc.Update(func(c *model.Config) {
		c.SelfService = "https://192.168.57.33:8800/home"
	})
	u, err := authSvc.GenerateSSOURL(ctx, "")
	if err != nil || u != "https://192.168.57.33:8800/home" {
		t.Fatalf("expected https://192.168.57.33:8800/home, got %s (err: %v)", u, err)
	}

	// 3. Omitted protocol with :8800 port
	_ = cfgSvc.Update(func(c *model.Config) {
		c.SelfService = "192.168.57.33:8800/home"
	})
	u, err = authSvc.GenerateSSOURL(ctx, "")
	if err != nil || u != "https://192.168.57.33:8800/home" {
		t.Fatalf("expected auto-https for :8800, got %s (err: %v)", u, err)
	}

	// 4. Regular HTTP domain
	_ = cfgSvc.Update(func(c *model.Config) {
		c.SelfService = "zfw.school.edu.cn/selfservice"
	})
	u, err = authSvc.GenerateSSOURL(ctx, "")
	if err != nil || u != "http://zfw.school.edu.cn/selfservice" {
		t.Fatalf("expected auto-http for standard domain, got %s (err: %v)", u, err)
	}
}

func TestCircuitBreaker_Lifecycle(t *testing.T) {
	cb := NewCircuitBreaker()
	if !cb.CanExecute() {
		t.Fatalf("new circuit breaker should be Closed (CanExecute=true)")
	}

	// Trip breaker
	cb.Trip("password_error")
	if cb.CanExecute() {
		t.Fatalf("tripped breaker should be Open (CanExecute=false)")
	}
	state, reason := cb.GetStatus()
	if state != BreakerOpen || reason != "password_error" {
		t.Fatalf("expected BreakerOpen with reason password_error, got %v / %s", state, reason)
	}

	// Reset breaker
	cb.Reset()
	if !cb.CanExecute() {
		t.Fatalf("reset breaker should be Closed (CanExecute=true)")
	}
}

func TestIsFatalAuthError(t *testing.T) {
	cases := []struct {
		errText string
		fatal   bool
	}{
		{"E2531: Password error", true},
		{"user_tab_error: user not found", true},
		{"Arrears error: please pay bill", true},
		{"status_error: account disabled", true},
		{"auth_info_error", true},
		{"timeout: context deadline exceeded", false},
		{"connection refused", false},
		{"network is unreachable", false},
	}

	for _, c := range cases {
		got := IsFatalAuthError(c.errText)
		if got != c.fatal {
			t.Errorf("IsFatalAuthError(%q) = %v, want %v", c.errText, got, c.fatal)
		}
	}
}

