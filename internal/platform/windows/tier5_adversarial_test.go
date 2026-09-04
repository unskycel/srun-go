package windows

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestTier5_Winutil_ToastAdversarialPayloads tests ShowToast with extreme, malicious,
// XML injection, unicode, emoji, and massive payload strings.
func TestTier5_Winutil_ToastAdversarialPayloads(t *testing.T) {
	adversarialPayloads := []struct {
		name    string
		title   string
		message string
		icon    string
	}{
		{"XML Entities", "<script>alert('xss')</script>", "Test & < > \" ' payload", ""},
		{"XML Tag Injection", "</text><text>Injected tag</text>", "<!-- comment --> <![CDATA[cdata]]>", ""},
		{"Unicode and Emojis", "校园网认证通知 🚀 🌐", "登录成功！ IP: 10.200.21.50 🔒 💥 🌈", ""},
		{"Long String (5000 chars)", strings.Repeat("A", 5000), strings.Repeat("中文测试", 1000), ""},
		{"Empty Title and Message", "", "", ""},
		{"Invalid Icon Path", "Title", "Message", `Z:\NonExistent\Path\invalid_icon.png`},
		{"Special Path Characters", "Title", "Message", `C:\Path With Spaces & Symbols\icon's "test".png`},
	}

	for _, tc := range adversarialPayloads {
		t.Run(tc.name, func(t *testing.T) {
			err := ShowToast(tc.title, tc.message, tc.icon)
			if err != nil {
				t.Errorf("ShowToast failed on payload '%s': %v", tc.name, err)
			}
		})
	}

	// Rapid burst toast calls (concurrency stress on toastMutex)
	var wg sync.WaitGroup
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = ShowToast(fmt.Sprintf("Burst Title %d", idx), fmt.Sprintf("Burst Message %d", idx), "")
		}(i)
	}
	wg.Wait()
}

// TestTier5_Winutil_MutexAdversarial tests named Win32 mutex under extreme names,
// concurrent contention races, and handle safety.
func TestTier5_Winutil_MutexAdversarial(t *testing.T) {
	// 1. Mutex with empty name (falls back to DefaultMutexName)
	h, _, err := CreateSingleInstanceMutex("")
	if err != nil {
		t.Fatalf("CreateSingleInstanceMutex('') failed: %v", err)
	}
	_ = ReleaseSingleInstanceMutex(h)

	// 2. Mutex with Chinese & Unicode characters
	unicodeName := fmt.Sprintf("Local\\校园网互斥锁_Test_%d", time.Now().UnixNano())
	hUni, exists, err := CreateSingleInstanceMutex(unicodeName)
	if err != nil {
		t.Fatalf("CreateSingleInstanceMutex with unicode failed: %v", err)
	}
	if exists {
		t.Errorf("unexpected alreadyExists = true on unique unicode mutex")
	}
	_ = ReleaseSingleInstanceMutex(hUni)

	// 3. Safe handle release with 0 and InvalidHandle
	if err := ReleaseSingleInstanceMutex(0); err != nil {
		t.Errorf("ReleaseSingleInstanceMutex(0) returned error: %v", err)
	}
	if err := ReleaseSingleInstanceMutex(windows.InvalidHandle); err != nil {
		t.Errorf("ReleaseSingleInstanceMutex(InvalidHandle) returned error: %v", err)
	}

	// 4. High concurrency contention test (30 goroutines contending on unique mutex)
	sharedName := fmt.Sprintf("Local\\SRun_Contention_%d", time.Now().UnixNano())
	var wg sync.WaitGroup
	createdCount := int32(0)
	alreadyExistsCount := int32(0)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			handle, alreadyRunning, e := CreateSingleInstanceMutex(sharedName)
			if e == nil && handle != 0 {
				if alreadyRunning {
					alreadyExistsCount++
				} else {
					createdCount++
				}
				// Hold briefly then release
				time.Sleep(10 * time.Millisecond)
				_ = ReleaseSingleInstanceMutex(handle)
			}
		}()
	}
	wg.Wait()

	t.Logf("Contention test results: created=%d, alreadyExists=%d", createdCount, alreadyExistsCount)
}

// TestTier5_Winutil_StartupAndThemeAdversarial tests startup toggle cycling, theme defaults,
// and massive tray menus.
func TestTier5_Winutil_StartupAndThemeAdversarial(t *testing.T) {
	// 1. Rapid startup toggle cycling
	testExe := `C:\Program Files\SRun Authenticator\srun.exe`
	for iter := 0; iter < 10; iter++ {
		if err := SetAutoStart(true, testExe); err != nil {
			t.Fatalf("SetAutoStart(true) failed on iter %d: %v", iter, err)
		}
		if !IsAutoStartEnabled() {
			t.Fatalf("IsAutoStartEnabled() false after enable on iter %d", iter)
		}
		if err := SetAutoStart(false, ""); err != nil {
			t.Fatalf("SetAutoStart(false) failed on iter %d: %v", iter, err)
		}
		if IsAutoStartEnabled() {
			t.Fatalf("IsAutoStartEnabled() true after disable on iter %d", iter)
		}
	}

	// 2. Theme Icon Paths
	if GetThemeIconPath(true) != "icons/journey.png" {
		t.Errorf("GetThemeIconPath(true) != icons/journey.png")
	}
	if GetThemeIconPath(false) != "icons/journey_white.png" {
		t.Errorf("GetThemeIconPath(false) != icons/journey_white.png")
	}

	// 3. Massive Tray Menu structure (100 items + nested submenus)
	menu := NewTrayMenu()
	for i := 0; i < 100; i++ {
		item := menu.AddItem(fmt.Sprintf("Item %d", i), nil)
		if item == nil || item.ID == 0 {
			t.Fatalf("Failed to create menu item %d", i)
		}
	}
	subMenu := NewTrayMenu()
	for j := 0; j < 20; j++ {
		subMenu.AddCheckbox(fmt.Sprintf("Sub Item %d", j), j%2 == 0, nil)
	}
	menu.AddSubMenu("Submenu Category", subMenu)

	// Verify lookups
	found := menu.FindItemByID(1050)
	if found != nil {
		t.Logf("Found item 1050: %s", found.Title)
	}
}

