package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"srun/internal/domain/model"
	"srun/internal/platform/windows"
	"srun/internal/service"
)

type WindowController interface {
	Minimize()
	Close()
	Restore()
}

// BridgeHandler coordinates IPC requests between WebView2 and Domain Services.
type BridgeHandler struct {
	cfgSvc  *service.ConfigService
	netSvc  *service.NetworkService
	authSvc *service.AuthService
	winCtrl WindowController
}

func NewBridgeHandler(cfgSvc *service.ConfigService, netSvc *service.NetworkService, authSvc *service.AuthService, winCtrl WindowController) *BridgeHandler {
	return &BridgeHandler{
		cfgSvc:  cfgSvc,
		netSvc:  netSvc,
		authSvc: authSvc,
		winCtrl: winCtrl,
	}
}

// Dispatch handles string-based JSON-RPC dispatch from window.chrome.webview.
func (h *BridgeHandler) Dispatch(method string, args []any) (any, error) {
	switch method {
	case "get_config":
		return h.GetConfig()
	case "set_config":
		return h.SetConfig(args)
	case "get_ip_settings":
		return h.GetIPSettings()
	case "update_ip_settings":
		return h.UpdateIPSettings(args)
	case "probe_gateway_ips":
		return h.ProbeGatewayIPs(args)
	case "login":
		return h.Login(args)
	case "logout":
		return h.Logout(args)
	case "get_online_data":
		return h.GetOnlineData(args)
	case "start_self_service":
		return h.StartSelfService(args)
	case "reset_config":
		return h.ResetConfig()
	case "set_active_client_ip", "set_active_ip":
		return h.SetActiveClientIP(args)
	case "get_accounts":
		return h.GetAccounts()
	case "switch_account":
		return h.SwitchAccount(args)
	case "save_account":
		return h.SaveAccount(args)
	case "delete_account":
		return h.DeleteAccount(args)
	case "get_logs":
		return h.GetLogs()
	case "clear_logs":
		return h.ClearLogs()
	case "minimize_window":
		if h.winCtrl != nil {
			h.winCtrl.Minimize()
		}
		return nil, nil
	case "close_window":
		if h.winCtrl != nil {
			h.winCtrl.Close()
		}
		return nil, nil
	case "webbrowser_open":
		if len(args) > 0 {
			if targetURL, ok := args[0].(string); ok && targetURL != "" {
				_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", targetURL).Start()
			}
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown method: %s", method)
	}
}

func (h *BridgeHandler) GetConfig() (ConfigDTO, error) {
	cfg := h.cfgSvc.GetConfigCopy()
	plainPwd, _ := cfg.GetPlainPassword()

	gw := cfg.SrunHost
	if gw == "" {
		gw = cfg.HostIP
	}

	accounts := cfg.GetAccounts()
	accountDTOs := make([]AccountDTO, 0, len(accounts))
	for _, acc := range accounts {
		pwd, _ := acc.GetPlainPassword()
		accountDTOs = append(accountDTOs, AccountDTO{
			Username:    acc.Username,
			Remark:      acc.Remark,
			HasPassword: pwd != "" || acc.Password != "",
			IsActive:    acc.Username == cfg.Username,
			AutoLogin:   acc.AutoLogin,
		})
	}

	return ConfigDTO{
		Username:      cfg.Username,
		HasPassword:   plainPwd != "",
		Accounts:      accountDTOs,
		ActiveUser:    cfg.ActiveUser,
		AutoLogin:     cfg.AutoLogin,
		AutoReconnect: cfg.AutoReconnect,
		AutoStart:     cfg.StartWithWindows || windows.IsAutoStartEnabled(),
		Sleeptime:     cfg.Sleeptime,
		Gateway:       gw,
		SelfService:   cfg.SelfService,
		ActiveIP:      cfg.ActiveIP,
		LocalIPs:      cfg.LocalIPs,
	}, nil
}

func (h *BridgeHandler) GetAccounts() ([]AccountDTO, error) {
	cfg := h.cfgSvc.GetConfigCopy()
	accounts := cfg.GetAccounts()
	res := make([]AccountDTO, 0, len(accounts))
	for _, acc := range accounts {
		pwd, _ := acc.GetPlainPassword()
		res = append(res, AccountDTO{
			Username:    acc.Username,
			Remark:      acc.Remark,
			HasPassword: pwd != "" || acc.Password != "",
			IsActive:    acc.Username == cfg.Username,
			AutoLogin:   acc.AutoLogin,
		})
	}
	return res, nil
}

func (h *BridgeHandler) SwitchAccount(args []any) (ConfigDTO, error) {
	if len(args) == 0 {
		return ConfigDTO{}, fmt.Errorf("missing username parameter")
	}
	username, ok := args[0].(string)
	if !ok || strings.TrimSpace(username) == "" {
		return ConfigDTO{}, fmt.Errorf("invalid username")
	}

	err := h.cfgSvc.Update(func(c *model.Config) {
		_ = c.SwitchAccount(username)
	})
	if err != nil {
		return ConfigDTO{}, err
	}
	return h.GetConfig()
}

func (h *BridgeHandler) SaveAccount(args []any) (ConfigDTO, error) {
	if len(args) == 0 {
		return ConfigDTO{}, fmt.Errorf("missing account payload")
	}

	rawMap, ok := args[0].(map[string]any)
	if !ok {
		return ConfigDTO{}, fmt.Errorf("invalid account payload")
	}

	username, _ := rawMap["username"].(string)
	password, _ := rawMap["password"].(string)
	remark, _ := rawMap["remark"].(string)
	autoLogin, _ := rawMap["auto_login"].(bool)

	username = strings.TrimSpace(username)
	if username == "" {
		return ConfigDTO{}, fmt.Errorf("账号不能为空")
	}

	err := h.cfgSvc.Update(func(c *model.Config) {
		_ = c.SaveOrUpdateAccount(username, password, remark, autoLogin)
	})
	if err != nil {
		return ConfigDTO{}, err
	}

	return h.GetConfig()
}

func (h *BridgeHandler) DeleteAccount(args []any) (ConfigDTO, error) {
	if len(args) == 0 {
		return ConfigDTO{}, fmt.Errorf("missing username parameter")
	}
	username, ok := args[0].(string)
	if !ok || strings.TrimSpace(username) == "" {
		return ConfigDTO{}, fmt.Errorf("invalid username")
	}

	err := h.cfgSvc.Update(func(c *model.Config) {
		_ = c.DeleteAccount(username)
	})
	if err != nil {
		return ConfigDTO{}, err
	}

	return h.GetConfig()
}

func (h *BridgeHandler) SetConfig(args []any) (bool, error) {
	if len(args) == 0 {
		return false, fmt.Errorf("missing config payload")
	}

	var username string
	var password string
	var autoLogin bool
	hasAutoLogin := false
	var autoStart bool
	hasAutoStart := false
	var autoReconnect bool
	hasAutoReconnect := false
	var sleeptime int

	// Parse incoming JSON map
	if rawMap, ok := args[0].(map[string]any); ok {
		if u, ok := rawMap["username"].(string); ok {
			username = u
		}
		if p, ok := rawMap["password"].(string); ok {
			password = p
		}
		if al, ok := rawMap["auto_login"].(bool); ok {
			autoLogin = al
			hasAutoLogin = true
		}
		if as, ok := rawMap["auto_start"].(bool); ok {
			autoStart = as
			hasAutoStart = true
		}
		if ar, ok := rawMap["auto_reconnect"].(bool); ok {
			autoReconnect = ar
			hasAutoReconnect = true
		}
		if st, ok := rawMap["sleeptime"].(float64); ok {
			sleeptime = int(st)
		}
	}

	err := h.cfgSvc.Update(func(c *model.Config) {
		if username != "" {
			c.Username = username
			accAutoLogin := c.AutoLogin
			if hasAutoLogin {
				accAutoLogin = autoLogin
			}
			_ = c.SaveOrUpdateAccount(username, password, "", accAutoLogin)
		} else if password != "" {
			_ = c.SetPlainPassword(password)
		}
		if hasAutoLogin {
			c.AutoLogin = autoLogin
		}
		if hasAutoStart {
			c.StartWithWindows = autoStart
		}
		if hasAutoReconnect {
			c.AutoReconnect = autoReconnect
		}
		if sleeptime > 0 {
			c.Sleeptime = sleeptime
		}
	})
	if err != nil {
		return false, err
	}

	if hasAutoStart {
		_ = windows.SetAutoStart(autoStart, "")
	}
	return true, nil
}

func (h *BridgeHandler) GetIPSettings() (IPSettingsDTO, error) {
	cfg := h.cfgSvc.GetConfigCopy()
	availIPs, _ := h.netSvc.GetLocalIPv4List()

	gw := cfg.SrunHost
	if gw == "" {
		gw = cfg.HostIP
	}

	return IPSettingsDTO{
		Available:     availIPs,
		Selected:      cfg.LocalIPs,
		Active:        cfg.ActiveIP,
		Gateway:       gw,
		SelfService:   cfg.SelfService,
		AutoReconnect: cfg.AutoReconnect,
		AutoStart:     cfg.StartWithWindows || windows.IsAutoStartEnabled(),
		Sleeptime:     cfg.Sleeptime,
	}, nil
}

func (h *BridgeHandler) UpdateIPSettings(args []any) (bool, error) {
	if len(args) == 0 {
		return false, fmt.Errorf("missing settings payload")
	}

	var gateway, selfService string
	var selected []*string
	var active *string
	var hasAutoStart, hasAutoReconnect bool
	var autoStartVal, autoReconnectVal bool
	var sleeptimeVal int

	if rawMap, ok := args[0].(map[string]any); ok {
		if g, ok := rawMap["gateway"].(string); ok {
			gateway = g
		}
		if ss, ok := rawMap["self_service"].(string); ok {
			selfService = ss
		}
		if as, ok := rawMap["auto_start"].(bool); ok {
			hasAutoStart = true
			autoStartVal = as
		}
		if ar, ok := rawMap["auto_reconnect"].(bool); ok {
			hasAutoReconnect = true
			autoReconnectVal = ar
		}
		if st, ok := rawMap["sleeptime"].(float64); ok {
			sleeptimeVal = int(st)
		}
		if rawSel, ok := rawMap["selected"].([]any); ok {
			for _, item := range rawSel {
				if item == nil {
					selected = append(selected, nil)
				} else if str, ok := item.(string); ok {
					clean := strings.TrimSpace(str)
					if clean == "" || strings.EqualFold(clean, "null") || strings.EqualFold(clean, "default") || strings.EqualFold(clean, "auto") {
						selected = append(selected, nil)
					} else {
						selected = append(selected, &clean)
					}
				}
			}
		}
		if rawAct, ok := rawMap["active"]; ok && rawAct != nil {
			if actStr, ok := rawAct.(string); ok {
				clean := strings.TrimSpace(actStr)
				if clean != "" && !strings.EqualFold(clean, "null") && !strings.EqualFold(clean, "default") && !strings.EqualFold(clean, "auto") {
					active = &clean
				}
			}
		}
	}

	err := h.cfgSvc.Update(func(c *model.Config) {
		if gateway != "" {
			c.SrunHost = gateway
		}
		c.SelfService = selfService
		if len(selected) > 0 {
			c.LocalIPs = selected
		}
		c.ActiveIP = active
		if hasAutoStart {
			c.StartWithWindows = autoStartVal
		}
		if hasAutoReconnect {
			c.AutoReconnect = autoReconnectVal
		}
		if sleeptimeVal > 0 {
			c.Sleeptime = sleeptimeVal
		}
	})
	if err != nil {
		return false, err
	}
	if hasAutoStart {
		_ = windows.SetAutoStart(autoStartVal, "")
	}
	return true, nil
}

func (h *BridgeHandler) ProbeGatewayIPs(args []any) (any, error) {
	var gw string
	if len(args) > 0 {
		if s, ok := args[0].(string); ok && s != "" {
			gw = s
		}
	}
	if gw == "" {
		cfg := h.cfgSvc.GetConfigCopy()
		gw = cfg.SrunHost
		if gw == "" {
			gw = cfg.HostIP
		}
	}
	if gw == "" {
		return nil, fmt.Errorf("gateway host is empty")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return h.netSvc.ProbeGateway(ctx, gw)
}

func (h *BridgeHandler) Login(args []any) (any, error) {
	var ip string
	if len(args) > 0 {
		ip = h.netSvc.NormalizeIPToken(args[0])
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	return h.authSvc.Login(ctx, ip)
}

func (h *BridgeHandler) Logout(args []any) (any, error) {
	var ip string
	if len(args) > 0 {
		ip = h.netSvc.NormalizeIPToken(args[0])
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	return h.authSvc.Logout(ctx, ip)
}

func (h *BridgeHandler) GetOnlineData(args []any) (OnlineDataDTO, error) {
	var ip string
	if len(args) > 0 {
		ip = h.netSvc.NormalizeIPToken(args[0])
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	info, err := h.authSvc.GetUserInfo(ctx, ip)
	if err != nil || info == nil {
		return OnlineDataDTO{
			IsAvailable: false,
			IsOnline:    false,
			Data:        map[string]any{},
		}, nil
	}

	dataMap := map[string]any{
		"client_ip":      info.ClientIP,
		"online_ip":      info.OnlineIP,
		"user_name":      info.UserName,
		"user_mac":       info.UserMac,
		"user_balance":   info.UserBalance,
		"sum_bytes":      info.UsedBytes,
		"all_bytes":      info.AllBytes,
		"user_time":      info.OnlineTime,
		"keepalive_time": info.KeepaliveTime,
	}

	return OnlineDataDTO{
		IsAvailable: info.IsAvailable,
		IsOnline:    info.IsOnline,
		Data:        dataMap,
	}, nil
}

func (h *BridgeHandler) StartSelfService(args []any) (any, error) {
	var ip string
	if len(args) > 0 {
		ip = h.netSvc.NormalizeIPToken(args[0])
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	targetURL, err := h.authSvc.GenerateSSOURL(ctx, ip)
	if err != nil {
		return nil, err
	}
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", targetURL).Start()
	return nil, nil
}

func (h *BridgeHandler) ResetConfig() (bool, error) {
	err := h.cfgSvc.Reset()
	return err == nil, err
}

func (h *BridgeHandler) SetActiveClientIP(args []any) (bool, error) {
	var targetIP *string
	if len(args) > 0 && args[0] != nil {
		ipStr := h.netSvc.NormalizeIPToken(args[0])
		if ipStr != "" {
			targetIP = &ipStr
		}
	}

	err := h.cfgSvc.Update(func(c *model.Config) {
		c.ActiveIP = targetIP
	})
	return err == nil, err
}

func (h *BridgeHandler) GetLogs() ([]LogEntryDTO, error) {
	entries := service.GetLogger().GetEntries()
	dtos := make([]LogEntryDTO, len(entries))
	for i, e := range entries {
		dtos[i] = LogEntryDTO{
			Timestamp: e.Timestamp,
			Level:     e.Level,
			Message:   e.Message,
		}
	}
	return dtos, nil
}

func (h *BridgeHandler) ClearLogs() (string, error) {
	service.GetLogger().Clear()
	return "ok", nil
}

func init() {
	_ = json.Marshal
}
