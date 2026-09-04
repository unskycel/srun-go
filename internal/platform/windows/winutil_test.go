package windows

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

func TestTheme_IsSystemUsesLightTheme(t *testing.T) {
	// Should not panic or crash, returns a valid boolean
	isLight := IsSystemUsesLightTheme()
	t.Logf("IsSystemUsesLightTheme returned: %v", isLight)
}

func TestTheme_GetSystemThemeMode(t *testing.T) {
	mode := GetSystemThemeMode()
	if mode != ThemeDark && mode != ThemeLight {
		t.Fatalf("expected mode 0 (Dark) or 1 (Light), got %d", mode)
	}
	t.Logf("Current system theme mode: %d", mode)
}

func TestTheme_GetThemeIconPath(t *testing.T) {
	lightPath := GetThemeIconPath(true)
	if lightPath != "icons/journey.png" {
		t.Errorf("expected 'icons/journey.png', got '%s'", lightPath)
	}

	darkPath := GetThemeIconPath(false)
	if darkPath != "icons/journey_white.png" {
		t.Errorf("expected 'icons/journey_white.png', got '%s'", darkPath)
	}
}

func TestStartup_SetAndCheck(t *testing.T) {
	fakeExe := `C:\Program Files\SRun\srun.exe`

	// Test enabling auto-start
	err := SetAutoStart(true, fakeExe)
	if err != nil {
		t.Fatalf("SetAutoStart(true) failed: %v", err)
	}

	if !IsAutoStartEnabled() {
		t.Errorf("expected IsAutoStartEnabled() to be true after enabling")
	}

	// Test disabling auto-start
	err = SetAutoStart(false, "")
	if err != nil {
		t.Fatalf("SetAutoStart(false) failed: %v", err)
	}

	if IsAutoStartEnabled() {
		t.Errorf("expected IsAutoStartEnabled() to be false after disabling")
	}
}

func TestStartup_ShortcutPaths(t *testing.T) {
	path := GetStartupShortcutPath()
	if !strings.HasSuffix(path, StartupShortcutName) {
		t.Errorf("expected shortcut path to end with '%s', got '%s'", StartupShortcutName, path)
	}
	t.Logf("Startup shortcut path: %s", path)
}

func TestStartup_SyncAutoStartAndHeal(t *testing.T) {
	deadExe := `Z:\NonExistent\Folder\dead_srun.exe`

	// 1. Manually write a dead path into registry to simulate old broken desktop path
	err := SetAutoStart(true, deadExe)
	if err != nil {
		t.Fatalf("SetAutoStart with dead path failed: %v", err)
	}
	defer func() {
		_ = SetAutoStart(false, "")
	}()

	// 2. Dead path should not be healthy
	if IsAutoStartHealthy("") {
		t.Errorf("expected dead path to report IsAutoStartHealthy() = false")
	}

	// 3. Now perform SyncAutoStart to heal it to a real executable
	realExe, err := resolveExecutablePath("")
	if err != nil {
		t.Fatalf("resolveExecutablePath failed: %v", err)
	}

	err = SyncAutoStart(true, realExe)
	if err != nil {
		t.Fatalf("SyncAutoStart(true) failed: %v", err)
	}

	regExe := GetRegistryStartupExe()
	if !strings.EqualFold(regExe, realExe) {
		t.Errorf("expected healed registry exe to be '%s', got '%s'", realExe, regExe)
	}

	// 4. SyncAutoStart(false) disables cleanly
	err = SyncAutoStart(false, "")
	if err != nil {
		t.Fatalf("SyncAutoStart(false) failed: %v", err)
	}

	if IsAutoStartEnabled() {
		t.Errorf("expected auto start to be disabled after SyncAutoStart(false)")
	}
}

func TestMutex_SingleInstance(t *testing.T) {
	uniqueName := fmt.Sprintf("Local\\SRun_Test_Mutex_%d", time.Now().UnixNano())

	// 1. First instance creates mutex
	h1, alreadyExists, err := CreateSingleInstanceMutex(uniqueName)
	if err != nil {
		t.Fatalf("CreateSingleInstanceMutex first call failed: %v", err)
	}
	defer ReleaseSingleInstanceMutex(h1)

	if alreadyExists {
		t.Errorf("first mutex creation should have alreadyExists = false")
	}

	// 2. Second instance attempts to create mutex with same name
	h2, alreadyExists2, err := CreateSingleInstanceMutex(uniqueName)
	if err != nil {
		t.Fatalf("CreateSingleInstanceMutex second call failed: %v", err)
	}
	defer ReleaseSingleInstanceMutex(h2)

	if !alreadyExists2 {
		t.Errorf("second mutex creation should have alreadyExists = true")
	}
}

func TestMutex_AcquireSingleInstanceMutex(t *testing.T) {
	uniqueName := fmt.Sprintf("Local\\SRun_Test_Acquire_%d", time.Now().UnixNano())

	release1, alreadyRunning1, err := AcquireSingleInstanceMutex(uniqueName)
	if err != nil {
		t.Fatalf("AcquireSingleInstanceMutex call 1 failed: %v", err)
	}
	if alreadyRunning1 {
		t.Errorf("first acquire should return alreadyRunning = false")
	}

	// Second acquire on same name
	release2, alreadyRunning2, err := AcquireSingleInstanceMutex(uniqueName)
	if err != nil {
		t.Fatalf("AcquireSingleInstanceMutex call 2 failed: %v", err)
	}
	if !alreadyRunning2 {
		t.Errorf("second acquire should return alreadyRunning = true")
	}

	// Release both
	release2()
	release1()
}

func TestConsole_ConstantsAndExecution(t *testing.T) {
	if ATTACH_PARENT_PROCESS != 0xFFFFFFFF {
		t.Errorf("expected ATTACH_PARENT_PROCESS to be 0xFFFFFFFF, got 0x%X", ATTACH_PARENT_PROCESS)
	}

	// Calling AttachParentConsole in a go test environment should safely return without panic
	_ = AttachParentConsole()
}

func TestToast_ShowToastNonBlocking(t *testing.T) {
	start := time.Now()
	err := ShowToast("SRun Test Notification", "This is an automated unit test toast notification", "")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("ShowToast returned error: %v", err)
	}

	// Because it's asynchronous, it should return virtually instantaneously (under 200ms)
	if elapsed > 500*time.Millisecond {
		t.Errorf("ShowToast took too long to return (%v), expected non-blocking execution", elapsed)
	}
}

func TestToast_ShowToastDebounced(t *testing.T) {
	key := "test_debounce_key"
	err1 := ShowToastDebounced(key, "Test 1", "Message 1", 10*time.Second)
	if err1 != nil {
		t.Fatalf("ShowToastDebounced call 1 failed: %v", err1)
	}

	// Immediate second call with same key should be debounced and return nil instantly
	err2 := ShowToastDebounced(key, "Test 2", "Message 2", 10*time.Second)
	if err2 != nil {
		t.Fatalf("ShowToastDebounced call 2 failed: %v", err2)
	}
}

func TestToast_EnsureAppUserModelIDRegistered(t *testing.T) {
	err := EnsureAppUserModelIDRegistered("")
	if err != nil {
		t.Fatalf("EnsureAppUserModelIDRegistered failed: %v", err)
	}

	// Verify registry entry exists in HKCU
	regPath := `Software\Classes\AppUserModelId\` + DefaultAppID
	k, err := registry.OpenKey(registry.CURRENT_USER, regPath, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("failed to open AppUserModelId key: %v", err)
	}
	defer k.Close()

	name, _, err := k.GetStringValue("DisplayName")
	if err != nil || name != "校园网登录器" {
		t.Errorf("expected DisplayName '校园网登录器', got '%s'", name)
	}

	show, _, err := k.GetIntegerValue("ShowInSettings")
	if err != nil || show != 1 {
		t.Errorf("expected ShowInSettings 1, got %d", show)
	}
}

func TestTray_MenuDataStructures(t *testing.T) {
	menu := NewTrayMenu()

	clicked := false
	loginItem := menu.AddItem("登录", func() {
		clicked = true
	})
	if loginItem.Title != "登录" || loginItem.ID == 0 {
		t.Errorf("invalid login item: %+v", loginItem)
	}

	menu.AddSeparator()

	autoLoginItem := menu.AddCheckbox("断线重连", true, nil)
	if !autoLoginItem.Checked || autoLoginItem.Title != "断线重连" {
		t.Errorf("invalid auto login item: %+v", autoLoginItem)
	}

	subMenu := NewTrayMenu()
	ipItem := subMenu.AddItem("10.200.21.50", nil)
	menu.AddSubMenu("联网接口", subMenu)

	// Test find by ID
	found := menu.FindItemByID(loginItem.ID)
	if found == nil || found.Title != "登录" {
		t.Errorf("FindItemByID failed for loginItem")
	}

	foundSub := menu.FindItemByID(ipItem.ID)
	if foundSub == nil || foundSub.Title != "10.200.21.50" {
		t.Errorf("FindItemByID failed for subMenu item")
	}

	// Verify click handler execution
	loginItem.OnClick()
	if !clicked {
		t.Errorf("loginItem.OnClick() was not triggered")
	}
}

func TestTray_BuildWin32PopupMenu(t *testing.T) {
	menu := NewTrayMenu()
	menu.AddItem("打开主界面", nil)
	menu.AddSeparator()
	menu.AddCheckbox("开机自启", false, nil)
	menu.AddItem("退出", nil)

	handlers := make(map[uint32]func())
	hMenu, err := BuildWin32PopupMenu(menu, handlers)
	if err != nil {
		t.Fatalf("BuildWin32PopupMenu failed: %v", err)
	}
	if hMenu == 0 {
		t.Fatalf("BuildWin32PopupMenu returned 0 handle")
	}

	// Cleanup
	DestroyWin32Menu(hMenu)
}

func TestTray_NOTIFYICONDATASize(t *testing.T) {
	var nid NOTIFYICONDATAW
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	if nid.CbSize == 0 {
		t.Errorf("invalid NOTIFYICONDATAW size calculation")
	}
}

func TestTrimWorkingSet(t *testing.T) {
	// TrimWorkingSet should execute safely without error or panic
	TrimWorkingSet()
	TrimWorkingSetDelayed(10 * time.Millisecond)
	time.Sleep(30 * time.Millisecond)
}


