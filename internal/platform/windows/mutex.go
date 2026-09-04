package windows

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// DefaultMutexName is the default named mutex identifier for SRun single-instance locking.
	DefaultMutexName = "Local\\SRun_SingleInstance_Mutex"
)

// CreateSingleInstanceMutex creates or opens a named Win32 mutex for single-instance enforcement.
// Returns:
// - handle: the Windows mutex handle (must be closed upon program exit)
// - alreadyExists: true if another instance has already created this mutex (ERROR_ALREADY_EXISTS)
// - err: non-nil if Win32 CreateMutex call failed
func CreateSingleInstanceMutex(name string) (windows.Handle, bool, error) {
	if name == "" {
		name = DefaultMutexName
	}
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, false, fmt.Errorf("invalid mutex name: %w", err)
	}

	handle, err := windows.CreateMutex(nil, false, namePtr)
	if handle == 0 {
		return 0, false, fmt.Errorf("CreateMutex failed: %w", err)
	}

	alreadyExists := (err == windows.ERROR_ALREADY_EXISTS)
	return handle, alreadyExists, nil
}

// ReleaseSingleInstanceMutex releases and closes the specified mutex handle.
func ReleaseSingleInstanceMutex(handle windows.Handle) error {
	if handle != 0 && handle != windows.InvalidHandle {
		return windows.CloseHandle(handle)
	}
	return nil
}

// AcquireSingleInstanceMutex acquires the single instance lock and returns a cleanup function,
// an alreadyRunning flag, and an error if creation failed.
func AcquireSingleInstanceMutex(name string) (releaseFunc func(), alreadyRunning bool, err error) {
	handle, alreadyExists, err := CreateSingleInstanceMutex(name)
	if err != nil {
		return nil, false, err
	}
	release := func() {
		_ = ReleaseSingleInstanceMutex(handle)
	}
	return release, alreadyExists, nil
}

var (
	procFindWindowW = dllUser32.NewProc("FindWindowW")
	procShowWindow  = dllUser32.NewProc("ShowWindow")
)

const SW_RESTORE = 9

// WakeExistingWindow finds an existing window by title and restores it to the foreground.
func WakeExistingWindow(windowTitle string) bool {
	titlePtr, err := windows.UTF16PtrFromString(windowTitle)
	if err != nil {
		return false
	}
	hwnd, _, _ := procFindWindowW.Call(0, uintptr(unsafe.Pointer(titlePtr)))
	if hwnd != 0 {
		procShowWindow.Call(hwnd, uintptr(SW_RESTORE))
		procSetForegroundWindow.Call(hwnd)
		return true
	}
	return false
}

