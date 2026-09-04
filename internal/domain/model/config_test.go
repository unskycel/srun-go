package model

import (
	"testing"
)

func TestConfig_MultiAccountLifecycle(t *testing.T) {
	cfg := DefaultConfig()

	// 1. Legacy migration test
	cfg.Username = "user1"
	_ = cfg.SetPlainPassword("pwd1")
	cfg.AutoLogin = true

	accounts := cfg.GetAccounts()
	if len(accounts) != 1 {
		t.Fatalf("expected 1 migrated account, got %d", len(accounts))
	}
	if accounts[0].Username != "user1" || accounts[0].AutoLogin != true {
		t.Fatalf("unexpected account: %+v", accounts[0])
	}
	pwd1, err := cfg.GetPlainPassword()
	if err != nil || pwd1 != "pwd1" {
		t.Fatalf("expected pwd1, got %s, err: %v", pwd1, err)
	}

	// 2. Add second account
	err = cfg.SaveOrUpdateAccount("user2", "pwd2", "备用学号", false)
	if err != nil {
		t.Fatalf("SaveOrUpdateAccount failed: %v", err)
	}
	if len(cfg.Accounts) != 2 {
		t.Fatalf("expected 2 accounts, got %d", len(cfg.Accounts))
	}

	// user1 is still active
	if cfg.ActiveUser != "user1" || cfg.Username != "user1" {
		t.Fatalf("expected user1 active, got ActiveUser=%s Username=%s", cfg.ActiveUser, cfg.Username)
	}

	// 3. Switch to user2
	err = cfg.SwitchAccount("user2")
	if err != nil {
		t.Fatalf("SwitchAccount failed: %v", err)
	}
	if cfg.ActiveUser != "user2" || cfg.Username != "user2" || cfg.AutoLogin != false {
		t.Fatalf("switch failed: active=%s, username=%s, autologin=%v", cfg.ActiveUser, cfg.Username, cfg.AutoLogin)
	}
	pwd2, err := cfg.GetPlainPassword()
	if err != nil || pwd2 != "pwd2" {
		t.Fatalf("expected pwd2, got %s, err: %v", pwd2, err)
	}

	// 4. Update user2 remark
	err = cfg.SaveOrUpdateAccount("user2", "", "主用学号", true)
	if err != nil {
		t.Fatalf("update account failed: %v", err)
	}
	if cfg.AutoLogin != true {
		t.Fatalf("expected autoLogin=true, got %v", cfg.AutoLogin)
	}
	pwd2Still, _ := cfg.GetPlainPassword()
	if pwd2Still != "pwd2" {
		t.Fatalf("password should be preserved when plainPwd is empty, got %s", pwd2Still)
	}

	// 5. Delete active account user2
	err = cfg.DeleteAccount("user2")
	if err != nil {
		t.Fatalf("DeleteAccount failed: %v", err)
	}
	if len(cfg.Accounts) != 1 {
		t.Fatalf("expected 1 account remaining, got %d", len(cfg.Accounts))
	}
	// Active account should auto-fallback to user1
	if cfg.ActiveUser != "user1" || cfg.Username != "user1" {
		t.Fatalf("expected active user to fallback to user1, got %s", cfg.ActiveUser)
	}
}
