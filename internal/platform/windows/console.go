package windows

import (
	"os"

	"golang.org/x/sys/windows"
)

const (
	// ATTACH_PARENT_PROCESS indicates attaching to the console of the parent process.
	ATTACH_PARENT_PROCESS = ^uint32(0) // (DWORD)-1 or 0xFFFFFFFF
)

var (
	dllKernel32       = windows.NewLazySystemDLL("kernel32.dll")
	procAttachConsole = dllKernel32.NewProc("AttachConsole")
	procAllocConsole  = dllKernel32.NewProc("AllocConsole")
	procFreeConsole   = dllKernel32.NewProc("FreeConsole")
)

// AttachParentConsole attempts to attach the current process to the console of its parent process.
// If successful, standard output, standard error, and standard input streams are redirected
// to CONOUT$ and CONIN$, enabling CLI output for GUI-subsystem binaries.
// Returns true if attached, false otherwise.
func AttachParentConsole() bool {
	r, _, _ := procAttachConsole.Call(uintptr(ATTACH_PARENT_PROCESS))
	if r != 0 {
		// Redirect standard output and error to console output stream
		if stdout, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
			os.Stdout = stdout
		}
		if stderr, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
			os.Stderr = stderr
		}
		if stdin, err := os.OpenFile("CONIN$", os.O_RDONLY, 0); err == nil {
			os.Stdin = stdin
		}
		return true
	}
	return false
}

// AllocConsole allocates a new console for the calling process.
func AllocConsole() bool {
	r, _, _ := procAllocConsole.Call()
	if r != 0 {
		if stdout, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
			os.Stdout = stdout
		}
		if stderr, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
			os.Stderr = stderr
		}
		if stdin, err := os.OpenFile("CONIN$", os.O_RDONLY, 0); err == nil {
			os.Stdin = stdin
		}
		return true
	}
	return false
}

// FreeConsole detaches the calling process from its console.
func FreeConsole() bool {
	r, _, _ := procFreeConsole.Call()
	return r != 0
}

