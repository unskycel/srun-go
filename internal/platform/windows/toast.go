package windows

import (
	"context"
	"fmt"
	"html"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultAppID is the AUMID used for Windows toast notifications.
	DefaultAppID = "SRun.CampusNetwork"
)

var (
	toastMutex  sync.Mutex
	debounceMap = make(map[string]time.Time)
	debounceMu  sync.Mutex
)

// ShowToastDebounced shows a toast only if at least minInterval has elapsed since last toast with the given key.
func ShowToastDebounced(key, title, message string, minInterval time.Duration) error {
	if minInterval <= 0 {
		minInterval = 30 * time.Second
	}
	debounceMu.Lock()
	lastTime, exists := debounceMap[key]
	if exists && time.Since(lastTime) < minInterval {
		debounceMu.Unlock()
		return nil
	}
	debounceMap[key] = time.Now()
	debounceMu.Unlock()

	return ShowToast(title, message, "")
}

// ShowToast displays a native Windows desktop toast notification.
// It executes asynchronously in the background so it never blocks the caller or hangs.
// If title or message contains special XML characters, they are properly escaped.
func ShowToast(title, message, iconPath string) error {
	return ShowToastWithDuration(title, message, 5, iconPath)
}

// ShowToastWithDuration displays a native Windows desktop toast notification with a specified duration in seconds.
func ShowToastWithDuration(title, message string, durationSec int, iconPath string) error {
	if title == "" {
		title = "校园网登录器"
	}

	escapedTitle := html.EscapeString(title)
	escapedMessage := html.EscapeString(message)

	var imageTag string
	if iconPath != "" {
		if abs, err := filepath.Abs(iconPath); err == nil {
			imageTag = fmt.Sprintf(`<image placement="appLogoOverride" src="%s" />`, html.EscapeString(abs))
		}
	}

	xmlPayload := fmt.Sprintf(`<toast><visual><binding template="ToastGeneric"><text>%s</text><text>%s</text>%s</binding></visual></toast>`,
		escapedTitle,
		escapedMessage,
		imageTag,
	)

	// PowerShell script to display WinRT toast
	psScript := fmt.Sprintf(`
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml(@'
%s
'@)
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('%s').Show($toast)
`, xmlPayload, DefaultAppID)

	// Execute asynchronously in a detached goroutine with timeout
	go func() {
		toastMutex.Lock()
		defer toastMutex.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", psScript)
		_ = cmd.Run()
	}()

	return nil
}

// ShowToastSync displays a native toast synchronously with a timeout (for testing/CLI verification).
func ShowToastSync(title, message, iconPath string, timeout time.Duration) error {
	if title == "" {
		title = "校园网登录器"
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	escapedTitle := html.EscapeString(title)
	escapedMessage := html.EscapeString(message)

	var imageTag string
	if iconPath != "" {
		if abs, err := filepath.Abs(iconPath); err == nil {
			imageTag = fmt.Sprintf(`<image placement="appLogoOverride" src="%s" />`, html.EscapeString(abs))
		}
	}

	xmlPayload := fmt.Sprintf(`<toast><visual><binding template="ToastGeneric"><text>%s</text><text>%s</text>%s</binding></visual></toast>`,
		escapedTitle,
		escapedMessage,
		imageTag,
	)

	psScript := fmt.Sprintf(`
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml(@'
%s
'@)
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('%s').Show($toast)
`, xmlPayload, DefaultAppID)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", psScript)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("powershell toast notification failed (%s): %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

