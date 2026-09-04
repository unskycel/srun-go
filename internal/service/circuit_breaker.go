package service

import (
	"strings"
	"sync"
	"time"

	"srun/internal/platform/windows"
)

type BreakerState int

const (
	BreakerClosed BreakerState = iota // Normal operation
	BreakerOpen                       // Tripped: auto-login blocked to prevent account ban
)

// CircuitBreaker guards against infinite login loops with invalid credentials
// to prevent the campus gateway from locking or blacklisting student accounts.
type CircuitBreaker struct {
	mu            sync.RWMutex
	state         BreakerState
	trippedReason string
	trippedTime   time.Time
}

func NewCircuitBreaker() *CircuitBreaker {
	return &CircuitBreaker{
		state: BreakerClosed,
	}
}

// CanExecute returns true if the breaker allows automatic login attempt.
func (cb *CircuitBreaker) CanExecute() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state == BreakerClosed
}

// Trip trips the circuit breaker due to a critical authentication failure (wrong password, account arrears, etc.).
func (cb *CircuitBreaker) Trip(reason string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state = BreakerOpen
	cb.trippedReason = reason
	cb.trippedTime = time.Now()

	_ = windows.ShowToastDebounced("auth_fused", "校园网认证安全保护", "检测到账号或密码异常，已自动暂停重连以防账号被封禁。修改配置或手动连接后恢复。", 2*time.Minute)
}

// Reset resets the circuit breaker back to normal Closed state.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state = BreakerClosed
	cb.trippedReason = ""
}

// GetStatus returns the current state and reason.
func (cb *CircuitBreaker) GetStatus() (BreakerState, string) {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state, cb.trippedReason
}

// IsFatalAuthError detects whether an error indicates credential/account issues that should trip the breaker.
func IsFatalAuthError(errText string) bool {
	lower := strings.ToLower(errText)
	fatalKeywords := []string{
		"pass", "password", "user_tab_error", "user_not_found",
		"arrears", "mac_error", "disabled", "status_error",
		"auth_info_error", "not_found",
	}
	for _, kw := range fatalKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
