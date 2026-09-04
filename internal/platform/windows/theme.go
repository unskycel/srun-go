package windows

import (
	"golang.org/x/sys/windows/registry"
)

// ThemeMode represents the Windows taskbar theme mode (Dark or Light).
type ThemeMode int

const (
	// ThemeDark indicates a dark taskbar (value 0) requiring a white/light icon.
	ThemeDark ThemeMode = 0

	// ThemeLight indicates a light taskbar (value 1) requiring a dark icon.
	ThemeLight ThemeMode = 1

	// PersonalizeRegistryKey is the registry path where Windows stores theme settings.
	PersonalizeRegistryKey = `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`

	// SystemUsesLightThemeValue is the registry DWORD value name for taskbar theme.
	SystemUsesLightThemeValue = "SystemUsesLightTheme"
)

// IsSystemUsesLightTheme checks if the current Windows user has configured a light theme
// for system elements (such as the taskbar).
// It queries HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\SystemUsesLightTheme.
// If the key is missing, access denied, or not found, it safely falls back to true (light theme).
// If the value is 0, it returns false (dark theme).
func IsSystemUsesLightTheme() bool {
	k, err := registry.OpenKey(
		registry.CURRENT_USER,
		PersonalizeRegistryKey,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return true // Fallback to default light mode
	}
	defer k.Close()

	val, _, err := k.GetIntegerValue(SystemUsesLightThemeValue)
	if err != nil {
		return true // Fallback to default light mode
	}

	return val != 0
}

// GetSystemThemeMode returns ThemeLight (1) or ThemeDark (0) depending on system settings.
func GetSystemThemeMode() ThemeMode {
	if IsSystemUsesLightTheme() {
		return ThemeLight
	}
	return ThemeDark
}

// GetThemeIconPath returns the relative asset icon path suited for the given theme mode.
func GetThemeIconPath(isLight bool) string {
	if isLight {
		return "icons/journey.png"
	}
	return "icons/journey_white.png"
}

