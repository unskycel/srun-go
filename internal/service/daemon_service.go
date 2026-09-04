package service

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	"srun/internal/platform/windows"
)

// DaemonService manages background auto-reconnection with circuit breaker protection,
// jittered exponential backoff, and native system event integration.
type DaemonService struct {
	mu             sync.Mutex
	cfgSvc         *ConfigService
	authSvc        *AuthService
	cancel         context.CancelFunc
	circuitBreaker *CircuitBreaker
	triggerCh      chan struct{}
}

func NewDaemonService(cfgSvc *ConfigService, authSvc *AuthService) *DaemonService {
	return &DaemonService{
		cfgSvc:         cfgSvc,
		authSvc:        authSvc,
		circuitBreaker: NewCircuitBreaker(),
		triggerCh:      make(chan struct{}, 1),
	}
}

// ResetCircuitBreaker resets the authentication safety circuit breaker.
func (d *DaemonService) ResetCircuitBreaker() {
	d.circuitBreaker.Reset()
}

// TriggerCheck immediately triggers a check & reconnect probe.
func (d *DaemonService) TriggerCheck() {
	select {
	case d.triggerCh <- struct{}{}:
	default:
	}
}

// OnPowerResume handles system wake-up from sleep/hibernate with a burst probe sequence.
func (d *DaemonService) OnPowerResume() {
	LogEvent("捕获到 Windows 系统唤醒事件 (Power Resume)，启动突发自愈序列...")
	d.ResetCircuitBreaker()
	go func() {
		// Progressive burst sequence after waking from sleep:
		// WiFi adapter usually takes 1-3 seconds to re-associate with the AP.
		delays := []time.Duration{
			800 * time.Millisecond,
			2000 * time.Millisecond,
			4000 * time.Millisecond,
		}
		for _, delay := range delays {
			time.Sleep(delay)
			d.TriggerCheck()
		}
	}()
}

func (d *DaemonService) Start(parentCtx context.Context) {
	ctx, cancel := context.WithCancel(parentCtx)
	d.cancel = cancel

	go d.loop(ctx)
	// Initial trigger probe shortly after starting
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(300 * time.Millisecond):
			d.TriggerCheck()
		}
	}()
}

func (d *DaemonService) Stop() {
	if d.cancel != nil {
		d.cancel()
	}
}

func (d *DaemonService) loop(ctx context.Context) {
	netChangeCh := windows.ListenNetworkChange(ctx)

	failedCount := 0
	retryBackoffCount := 0

	performCheck := func() bool {
		cfg := d.cfgSvc.GetConfigCopy()
		if (!cfg.AutoLogin && !cfg.AutoReconnect) || !cfg.PassCorrect {
			return false
		}

		gw := cfg.SrunHost
		if gw == "" {
			gw = cfg.HostIP
		}
		if gw == "" {
			return false
		}

		var activeIP string
		if cfg.ActiveIP != nil {
			activeIP = *cfg.ActiveIP
		}

		userCtx, userCancel := context.WithTimeout(ctx, 3*time.Second)
		info, err := d.authSvc.GetUserInfo(userCtx, activeIP)
		userCancel()

		// Gateway unreachable (non-campus network or offline link), stay silent
		if err != nil || info == nil || !info.IsAvailable {
			return false
		}

		if !info.IsOnline {
			// Circuit breaker guard: stop hammering the gateway if credentials are bad
			if !d.circuitBreaker.CanExecute() {
				return false
			}

			LogInfo("检测到校园网离线，正在自动重连 (第 %d 次尝试)...", retryBackoffCount+1)

			loginCtx, loginCancel := context.WithTimeout(ctx, 5*time.Second)
			res, loginErr := d.authSvc.Login(loginCtx, activeIP)
			loginCancel()

			if loginErr == nil && res != nil && (res.Error == "ok" || strings.Contains(res.SucMsg, "login_ok") || strings.Contains(res.SucMsg, "successful")) {
				LogSuccess("自动重连成功！校园网已恢复在线")
				_ = windows.ShowToastDebounced("auto_login_ok", "校园网已连接", fmt.Sprintf("已自动连接账号：%s", cfg.Username), 2*time.Minute)
				failedCount = 0
				retryBackoffCount = 0
				d.circuitBreaker.Reset()
				return true
			}

			// Login failed, evaluate failure type
			failedCount++
			retryBackoffCount++

			errText := ""
			if res != nil {
				errText = strings.ToLower(res.Error + " " + res.ErrorMsg)
			}
			if loginErr != nil {
				errText += " " + strings.ToLower(loginErr.Error())
			}

			// Check for fatal credential error to trip circuit breaker and prevent account ban
			if IsFatalAuthError(errText) {
				LogWarn("凭据异常，触发防封号安全熔断器 (已暂停自动重试): %s", errText)
				d.circuitBreaker.Trip(errText)
				return false
			}

			if failedCount >= 3 {
				_ = windows.ShowToastDebounced("reconnect_fail", "校园网连接异常", "自动连接失败，请检查网关或网络状态", 2*time.Minute)
			}
			return false
		}

		// Online confirmed
		failedCount = 0
		retryBackoffCount = 0
		d.circuitBreaker.Reset()
		return true
	}

	getBackoffDuration := func(baseSec int) time.Duration {
		if retryBackoffCount == 0 {
			if baseSec < 2 {
				baseSec = 5
			}
			return time.Duration(baseSec) * time.Second
		}

		// Jittered Exponential Backoff
		shift := retryBackoffCount
		if shift > 4 {
			shift = 4
		}
		base := 2 << shift // 4s, 8s, 16s, 32s
		if base > 30 {
			base = 30
		}
		// Add +/- 500ms random jitter to avoid collision waves
		jitter := time.Duration(rand.Intn(1000)-500) * time.Millisecond
		backoff := time.Duration(base)*time.Second + jitter
		if backoff < 2*time.Second {
			backoff = 2 * time.Second
		}
		return backoff
	}

	for {
		cfg := d.cfgSvc.GetConfigCopy()
		interval := getBackoffDuration(cfg.Sleeptime)

		select {
		case <-ctx.Done():
			return
		case <-netChangeCh:
			// Network adapter or IP changed: reset backoff and check immediately
			LogEvent("捕获到 Windows 网卡/IP 状态变更事件")
			retryBackoffCount = 0
			time.Sleep(150 * time.Millisecond)
			performCheck()
		case <-d.triggerCh:
			// Immediate trigger (e.g. from power resume or manual invoke)
			performCheck()
		case <-time.After(interval):
			performCheck()
		}
	}
}
