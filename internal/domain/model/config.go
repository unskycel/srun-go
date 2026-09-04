package model

import (
	"fmt"
	"strings"

	"srun/internal/platform/windows"
)

// AccountItem represents a saved user credential entry.
type AccountItem struct {
	Username  string `json:"username"`
	Password  string `json:"password"`   // DPAPI encrypted
	Remark    string `json:"remark"`     // Optional user label e.g. "我的学号"
	AutoLogin bool   `json:"auto_login"` // Account-specific auto login flag
}

func (a *AccountItem) SetPlainPassword(plain string) error {
	if plain == "" {
		a.Password = ""
		return nil
	}
	enc, err := windows.DPAPIEncrypt(plain)
	if err != nil {
		return fmt.Errorf("failed to encrypt password: %w", err)
	}
	a.Password = enc
	return nil
}

func (a *AccountItem) GetPlainPassword() (string, error) {
	if a.Password == "" {
		return "", nil
	}
	return windows.DecryptPasswordWithFallback(a.Password, nil)
}

// Config represents application configuration persisted to config.json.
type Config struct {
	Username         string        `json:"username"`
	Password         string        `json:"password"`
	Accounts         []AccountItem `json:"accounts,omitempty"`
	ActiveUser       string        `json:"active_user,omitempty"`
	AutoLogin        bool          `json:"auto_login"`
	AutoReconnect    bool          `json:"auto_reconnect"`
	StartWithWindows bool          `json:"start_with_windows"`
	SrunHost         string        `json:"srun_host"`
	HostIP           string        `json:"host_ip,omitempty"`
	ACID             string        `json:"ac_id"`
	SelfService      string        `json:"self_service"`
	LocalIPs         []*string     `json:"local_ips"`
	ActiveIP         *string       `json:"active_ip"`
	Sleeptime        int           `json:"sleeptime"`
	PassCorrect      bool          `json:"pass_correct"`
	Theme            string        `json:"theme,omitempty"`
}

// DefaultConfig returns a new Config with clean zero defaults.
func DefaultConfig() *Config {
	return &Config{
		Username:         "",
		Password:         "",
		Accounts:         nil,
		ActiveUser:       "",
		AutoLogin:        false,
		AutoReconnect:    false,
		StartWithWindows: false,
		SrunHost:         "",
		HostIP:           "",
		ACID:             "1",
		SelfService:      "",
		LocalIPs:         []*string{nil},
		ActiveIP:         nil,
		Sleeptime:        5,
		PassCorrect:      true,
		Theme:            "auto",
	}
}

// SetPlainPassword encrypts password with DPAPI and stores in Config and active account.
func (c *Config) SetPlainPassword(plain string) error {
	if plain == "" {
		c.Password = ""
		return nil
	}
	enc, err := windows.DPAPIEncrypt(plain)
	if err != nil {
		return fmt.Errorf("failed to encrypt password: %w", err)
	}
	c.Password = enc

	// Synchronize active account password if present
	if c.Username != "" {
		c.MigrateLegacyAccount()
		for i := range c.Accounts {
			if c.Accounts[i].Username == c.Username {
				c.Accounts[i].Password = enc
				break
			}
		}
	}
	return nil
}

// GetPlainPassword decrypts stored password.
func (c *Config) GetPlainPassword() (string, error) {
	if c.Password == "" {
		return "", nil
	}
	return windows.DecryptPasswordWithFallback(c.Password, nil)
}

// MigrateLegacyAccount ensures any legacy standalone username is recorded in Accounts.
func (c *Config) MigrateLegacyAccount() {
	if len(c.Accounts) == 0 && c.Username != "" {
		c.Accounts = []AccountItem{
			{
				Username:  c.Username,
				Password:  c.Password,
				Remark:    "默认账号",
				AutoLogin: c.AutoLogin,
			},
		}
		c.ActiveUser = c.Username
	}
	if c.ActiveUser == "" && len(c.Accounts) > 0 {
		c.ActiveUser = c.Accounts[0].Username
	}
	for i := range c.Accounts {
		if c.Accounts[i].Username == c.Username {
			c.Accounts[i].AutoLogin = c.AutoLogin
			if c.Password != "" && c.Accounts[i].Password == "" {
				c.Accounts[i].Password = c.Password
			}
		}
	}
}

// GetAccounts returns the list of saved accounts, running migration if needed.
func (c *Config) GetAccounts() []AccountItem {
	c.MigrateLegacyAccount()
	return c.Accounts
}

// SaveOrUpdateAccount adds or updates an account entry and synchronizes if active.
func (c *Config) SaveOrUpdateAccount(username, plainPwd, remark string, autoLogin bool) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}

	c.MigrateLegacyAccount()

	var encryptedPwd string
	hasNewPassword := false
	if plainPwd != "" {
		enc, err := windows.DPAPIEncrypt(plainPwd)
		if err != nil {
			return fmt.Errorf("failed to encrypt password: %w", err)
		}
		encryptedPwd = enc
		hasNewPassword = true
	}

	found := false
	for i := range c.Accounts {
		if c.Accounts[i].Username == username {
			found = true
			if remark != "" {
				c.Accounts[i].Remark = remark
			}
			if hasNewPassword {
				c.Accounts[i].Password = encryptedPwd
			}
			c.Accounts[i].AutoLogin = autoLogin
			break
		}
	}

	if !found {
		c.Accounts = append(c.Accounts, AccountItem{
			Username:  username,
			Password:  encryptedPwd,
			Remark:    remark,
			AutoLogin: autoLogin,
		})
	}

	// If this is the active user or there was no active user, sync top-level fields
	if c.ActiveUser == "" || c.ActiveUser == username || c.Username == username || len(c.Accounts) == 1 {
		c.ActiveUser = username
		c.Username = username
		if hasNewPassword {
			c.Password = encryptedPwd
		}
		c.AutoLogin = autoLogin
	}

	return nil
}

// SwitchAccount sets the active account and updates top-level Username, Password, AutoLogin.
func (c *Config) SwitchAccount(username string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}

	c.MigrateLegacyAccount()

	for _, acc := range c.Accounts {
		if acc.Username == username {
			c.ActiveUser = acc.Username
			c.Username = acc.Username
			c.Password = acc.Password
			c.AutoLogin = acc.AutoLogin
			return nil
		}
	}

	return fmt.Errorf("account %s not found", username)
}

// DeleteAccount removes an account from the saved list.
func (c *Config) DeleteAccount(username string) error {
	username = strings.TrimSpace(username)
	c.MigrateLegacyAccount()

	newAccounts := make([]AccountItem, 0, len(c.Accounts))
	for _, acc := range c.Accounts {
		if acc.Username != username {
			newAccounts = append(newAccounts, acc)
		}
	}

	c.Accounts = newAccounts

	// If the deleted account was active, switch to next available or reset
	if c.ActiveUser == username || c.Username == username {
		if len(c.Accounts) > 0 {
			c.ActiveUser = c.Accounts[0].Username
			c.Username = c.Accounts[0].Username
			c.Password = c.Accounts[0].Password
			c.AutoLogin = c.Accounts[0].AutoLogin
		} else {
			c.ActiveUser = ""
			c.Username = ""
			c.Password = ""
			c.AutoLogin = false
		}
	}

	return nil
}
