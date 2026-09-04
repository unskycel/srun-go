package windows

import (
	"runtime"
	"runtime/debug"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procSetProcessWorkingSetSize = dllKernel32.NewProc("SetProcessWorkingSetSize")
	procCreateToolhelp32Snapshot = dllKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW          = dllKernel32.NewProc("Process32FirstW")
	procProcess32NextW           = dllKernel32.NewProc("Process32NextW")
	procGetCurrentProcessId      = dllKernel32.NewProc("GetCurrentProcessId")
	procGetCurrentProcess        = dllKernel32.NewProc("GetCurrentProcess")
	procOpenProcess              = dllKernel32.NewProc("OpenProcess")
	procCloseHandle              = dllKernel32.NewProc("CloseHandle")
)

const (
	TH32CS_SNAPPROCESS = 0x00000002
	PROCESS_SET_QUOTA  = 0x0100
	PROCESS_QUERY_INFO = 0x0400
)

type PROCESSENTRY32W struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [windows.MAX_PATH]uint16
}

// TrimWorkingSet forces Go GC, returns free heap to the OS, and instructs the Windows
// Virtual Memory Manager to page out unused working sets for both the main process
// and all WebView2 child processes.
func TrimWorkingSet() {
	runtime.GC()
	debug.FreeOSMemory()

	curProc, _, _ := procGetCurrentProcess.Call()
	if curProc != 0 && procSetProcessWorkingSetSize.Find() == nil {
		procSetProcessWorkingSetSize.Call(curProc, ^uintptr(0), ^uintptr(0))
	}

	curPid, _, _ := procGetCurrentProcessId.Call()
	if curPid == 0 {
		return
	}

	// Snapshot processes to find children (such as msedgewebview2.exe)
	if procCreateToolhelp32Snapshot.Find() != nil || procProcess32FirstW.Find() != nil {
		return
	}

	hSnap, _, _ := procCreateToolhelp32Snapshot.Call(uintptr(TH32CS_SNAPPROCESS), 0)
	if hSnap == 0 || hSnap == uintptr(windows.InvalidHandle) {
		return
	}
	defer procCloseHandle.Call(hSnap)

	var pe PROCESSENTRY32W
	pe.Size = uint32(unsafe.Sizeof(pe))

	ret, _, _ := procProcess32FirstW.Call(hSnap, uintptr(unsafe.Pointer(&pe)))
	for ret != 0 {
		if pe.ParentProcessID == uint32(curPid) && pe.ProcessID != uint32(curPid) {
			hChild, _, _ := procOpenProcess.Call(uintptr(PROCESS_SET_QUOTA|PROCESS_QUERY_INFO), 0, uintptr(pe.ProcessID))
			if hChild != 0 {
				procSetProcessWorkingSetSize.Call(hChild, ^uintptr(0), ^uintptr(0))
				procCloseHandle.Call(hChild)
			}
		}
		ret, _, _ = procProcess32NextW.Call(hSnap, uintptr(unsafe.Pointer(&pe)))
	}
}

// TrimWorkingSetDelayed runs TrimWorkingSet asynchronously after the given delay.
func TrimWorkingSetDelayed(delay time.Duration) {
	go func() {
		time.Sleep(delay)
		TrimWorkingSet()
	}()
}
