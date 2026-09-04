package windows

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	// RunRegistryKey is the registry path for Windows startup programs.
	RunRegistryKey = `Software\Microsoft\Windows\CurrentVersion\Run`

	// AppStartupName is the registry value name used for SRun auto-startup.
	AppStartupName = "SRun"

	// LegacyAppStartupName is the legacy registry value name used in earlier versions.
	LegacyAppStartupName = "SRunClient"

	// StartupShortcutName is the shortcut filename in the Windows Startup folder.
	StartupShortcutName = "校园网登录器.lnk"

	// LegacyStartupShortcutName is the legacy shortcut filename with typo.
	LegacyStartupShortcutName = "校园网登陆器.lnk"
)

func resolveExecutablePath(exePath string) (string, error) {
	if exePath == "" {
		var err error
		exePath, err = os.Executable()
		if err != nil {
			return "", fmt.Errorf("failed to determine executable path: %w", err)
		}
		// If running from go-build temporary folder (e.g. go run), fallback to srun.exe in current directory if found
		if strings.Contains(strings.ToLower(exePath), "go-build") {
			if cwdExe, err := filepath.Abs("srun.exe"); err == nil {
				if _, statErr := os.Stat(cwdExe); statErr == nil {
					exePath = cwdExe
				}
			}
		}
	}
	return filepath.Abs(exePath)
}

// SetAutoStart configures or removes auto-start entries in both HKCU Run registry and Windows Startup folder.
// When enabled, it registers the application with the argument "--no-auto-open".
// If exePath is empty, it automatically detects the current running executable.
func SetAutoStart(enable bool, exePath string) error {
	k, err := registry.OpenKey(
		registry.CURRENT_USER,
		RunRegistryKey,
		registry.SET_VALUE|registry.QUERY_VALUE,
	)
	if err != nil {
		return fmt.Errorf("failed to open Run registry key: %w", err)
	}
	defer k.Close()

	if enable {
		absPath, err := resolveExecutablePath(exePath)
		if err != nil {
			return fmt.Errorf("failed to resolve absolute executable path: %w", err)
		}

		cmd := fmt.Sprintf(`"%s" --no-auto-open`, absPath)
		if err := k.SetStringValue(AppStartupName, cmd); err != nil {
			return fmt.Errorf("failed to write Run registry value: %w", err)
		}
		// Clean up legacy key if present
		_ = k.DeleteValue(LegacyAppStartupName)

		// Dual assurance: also create shortcut in the Windows Startup folder
		_ = CreateStartupShortcut(absPath, "--no-auto-open")
		return nil
	}

	// Disable auto-start: clean up registry keys
	var lastErr error
	if err := k.DeleteValue(AppStartupName); err != nil && err != registry.ErrNotExist {
		lastErr = err
	}
	if err := k.DeleteValue(LegacyAppStartupName); err != nil && err != registry.ErrNotExist {
		if lastErr == nil {
			lastErr = err
		}
	}

	// Clean up startup folder shortcuts (current and legacy)
	if err := DeleteStartupShortcut(); err != nil && lastErr == nil {
		lastErr = err
	}
	return lastErr
}

// IsAutoStartEnabled checks whether auto-start is enabled via either registry or startup shortcut.
func IsAutoStartEnabled() bool {
	if IsStartupShortcutExists() {
		return true
	}

	k, err := registry.OpenKey(
		registry.CURRENT_USER,
		RunRegistryKey,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return false
	}
	defer k.Close()

	val, _, err := k.GetStringValue(AppStartupName)
	if err == nil && strings.TrimSpace(val) != "" {
		return true
	}

	// Check legacy key name
	val, _, err = k.GetStringValue(LegacyAppStartupName)
	return err == nil && strings.TrimSpace(val) != ""
}

// GetStartupShortcutPath returns the path to the shortcut file in the Windows Startup folder.
func GetStartupShortcutPath() string {
	appdata := os.Getenv("APPDATA")
	if appdata == "" {
		if dir, err := os.UserConfigDir(); err == nil && dir != "" {
			appdata = dir
		} else {
			appdata = "."
		}
	}
	return filepath.Join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup", StartupShortcutName)
}

// GetLegacyStartupShortcutPath returns the legacy typo path in the Windows Startup folder.
func GetLegacyStartupShortcutPath() string {
	appdata := os.Getenv("APPDATA")
	if appdata == "" {
		if dir, err := os.UserConfigDir(); err == nil && dir != "" {
			appdata = dir
		} else {
			appdata = "."
		}
	}
	return filepath.Join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup", LegacyStartupShortcutName)
}

// IsStartupShortcutExists checks if either current or legacy shortcut exists in the Windows Startup folder.
func IsStartupShortcutExists() bool {
	if _, err := os.Stat(GetStartupShortcutPath()); err == nil {
		return true
	}
	if _, err := os.Stat(GetLegacyStartupShortcutPath()); err == nil {
		return true
	}
	return false
}

// CreateStartupShortcut creates a .lnk shortcut in the Windows Startup folder via PowerShell WScript.Shell.
func CreateStartupShortcut(exePath string, args string) error {
	absPath, err := resolveExecutablePath(exePath)
	if err != nil {
		return fmt.Errorf("failed to resolve absolute path: %w", err)
	}

	shortcutPath := GetStartupShortcutPath()
	if err := os.MkdirAll(filepath.Dir(shortcutPath), 0755); err != nil {
		return fmt.Errorf("failed to create startup directory: %w", err)
	}

	if args == "" {
		args = "--no-auto-open"
	}

	workDir := filepath.Dir(absPath)
	psScript := fmt.Sprintf(
		`$WshShell = New-Object -ComObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%s'); $Shortcut.TargetPath = '%s'; $Shortcut.Arguments = '%s'; $Shortcut.WorkingDirectory = '%s'; $Shortcut.Save()`,
		strings.ReplaceAll(shortcutPath, `'`, `''`),
		strings.ReplaceAll(absPath, `'`, `''`),
		strings.ReplaceAll(args, `'`, `''`),
		strings.ReplaceAll(workDir, `'`, `''`),
	)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("powershell create shortcut failed (%s): %w", string(out), err)
	}

	// Remove legacy typo shortcut if exists
	_ = os.Remove(GetLegacyStartupShortcutPath())
	return nil
}

// DeleteStartupShortcut removes both current and legacy shortcuts in the Windows Startup folder if they exist.
func DeleteStartupShortcut() error {
	_ = os.Remove(GetLegacyStartupShortcutPath())
	path := GetStartupShortcutPath()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove startup shortcut: %w", err)
	}
	return nil
}
