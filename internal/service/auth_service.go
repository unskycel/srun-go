package service

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"srun/internal/domain/event"
	"srun/internal/domain/model"
	"srun/internal/protocol/srun"
)

// AuthService coordinates authentication, logout, status monitoring, and SSO generation.
type AuthService struct {
	mu        sync.RWMutex
	cfgSvc    *ConfigService
	netSvc    *NetworkService
	eventBus  *event.Bus
	state     model.SystemState
	lastError string
}

func NewAuthService(cfgSvc *ConfigService, netSvc *NetworkService, bus *event.Bus) *AuthService {
	return &AuthService{
		cfgSvc:   cfgSvc,
		netSvc:   netSvc,
		eventBus: bus,
		state:    model.StateOffline,
	}
}

func (s *AuthService) GetState() model.SystemState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

func (s *AuthService) setState(st model.SystemState) {
	s.mu.Lock()
	s.state = st
	s.mu.Unlock()

	if s.eventBus != nil {
		s.eventBus.Publish(event.Event{
			Type:    event.EventStateChanged,
			Payload: st,
		})
	}
}

func (s *AuthService) getClient(ip string) *srun.Client {
	cfg := s.cfgSvc.GetConfigCopy()
	gw := cfg.SrunHost
	if gw == "" {
		gw = cfg.HostIP
	}
	return srun.NewClient(gw, cfg.ACID, ip)
}

func (s *AuthService) Login(ctx context.Context, targetIP string) (*srun.PortalResponse, error) {
	cfg := s.cfgSvc.GetConfigCopy()
	if cfg.Username == "" {
		return nil, fmt.Errorf("username is empty")
	}

	plainPwd, err := cfg.GetPlainPassword()
	if err != nil || plainPwd == "" {
		return nil, fmt.Errorf("password is empty or decrypt failed: %w", err)
	}

	LogInfo("正在为账号 [%s] 发起校园网认证...", cfg.Username)
	s.setState(model.StateAuthenticating)

	client := s.getClient(targetIP)
	res, err := client.Login(ctx, cfg.Username, plainPwd)

	if err != nil {
		LogError("认证通信异常: %v", err)
		s.setState(model.StateOffline)
		if s.eventBus != nil {
			s.eventBus.Publish(event.Event{
				Type:    event.EventAuthFailed,
				Payload: err.Error(),
			})
		}
		return nil, err
	}

	if res != nil && (res.Error == "ok" || strings.Contains(res.SucMsg, "login_ok") || strings.Contains(res.SucMsg, "successful")) {
		LogSuccess("账号 [%s] 登录成功！", cfg.Username)
		s.setState(model.StateOnline)
		_ = s.cfgSvc.Update(func(c *model.Config) {
			c.PassCorrect = true
		})
		if s.eventBus != nil {
			s.eventBus.Publish(event.Event{
				Type:    event.EventAuthSuccess,
				Payload: res,
			})
		}
	} else {
		s.setState(model.StateOffline)
		errMsg := ""
		if res != nil {
			errMsg = res.ErrorMsg
			if errMsg == "" {
				errMsg = res.Error
			}
		}
		LogWarn("认证失败: %s", errMsg)
		if s.eventBus != nil {
			s.eventBus.Publish(event.Event{
				Type:    event.EventAuthFailed,
				Payload: errMsg,
			})
		}
	}

	return res, nil
}

func (s *AuthService) Logout(ctx context.Context, targetIP string) (*srun.PortalResponse, error) {
	cfg := s.cfgSvc.GetConfigCopy()
	LogInfo("正在注销账号 [%s]...", cfg.Username)
	client := s.getClient(targetIP)

	res, err := client.Logout(ctx, cfg.Username)
	s.setState(model.StateOffline)
	if err != nil {
		LogError("注销请求异常: %v", err)
	} else {
		LogSuccess("账号 [%s] 已注销下线", cfg.Username)
	}
	return res, err
}

func (s *AuthService) GetUserInfo(ctx context.Context, targetIP string) (*srun.UserInfo, error) {
	client := s.getClient(targetIP)
	info, err := client.GetUserInfo(ctx)
	if err == nil && info != nil && info.IsOnline {
		s.setState(model.StateOnline)
	} else if err == nil && info != nil && info.IsAvailable && !info.IsOnline {
		s.setState(model.StateOffline)
	}
	return info, err
}

func (s *AuthService) GenerateSSOURL(ctx context.Context, targetIP string) (string, error) {
	cfg := s.cfgSvc.GetConfigCopy()
	selfService := strings.TrimSpace(cfg.SelfService)
	if selfService == "" {
		return "", fmt.Errorf("self-service address not configured")
	}

	// Pure direct mode: open user configured URL directly
	if strings.HasPrefix(selfService, "http://") || strings.HasPrefix(selfService, "https://") {
		return selfService, nil
	}

	// If user omitted protocol, intelligently detect HTTPS ports (e.g. :8800, :8443, :443) or default to http://
	if strings.Contains(selfService, ":8800") || strings.Contains(selfService, ":8443") || strings.Contains(selfService, ":443") {
		return "https://" + selfService, nil
	}
	return "http://" + selfService, nil
}
