package windows

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Win32 Tray & Menu Constants
const (
	WM_USER          = 0x0400
	WM_TRAYICON      = WM_USER + 100
	WM_COMMAND       = 0x0111
	WM_CLOSE         = 0x0010
	WM_DESTROY       = 0x0002
	WM_RBUTTONUP     = 0x0205
	WM_LBUTTONUP     = 0x0202
	WM_LBUTTONDBLCLK = 0x0203

	NIM_ADD        = 0x00000000
	NIM_MODIFY     = 0x00000001
	NIM_DELETE     = 0x00000002
	NIM_SETVERSION = 0x00000004

	NIF_MESSAGE = 0x00000001
	NIF_ICON    = 0x00000002
	NIF_TIP     = 0x00000004
	NIF_STATE   = 0x00000008
	NIF_INFO    = 0x00000010
	NIF_GUID    = 0x00000020

	NIIF_NONE       = 0x00000000
	NIIF_INFO       = 0x00000001
	NIIF_WARNING    = 0x00000002
	NIIF_ERROR      = 0x00000003
	NIIF_LARGE_ICON = 0x00000020

	MF_STRING    = 0x00000000
	MF_GRAYED    = 0x00000001
	MF_DISABLED  = 0x00000002
	MF_CHECKED   = 0x00000008
	MF_POPUP     = 0x00000010
	MF_SEPARATOR = 0x00000800

	TPM_LEFTALIGN   = 0x0000
	TPM_BOTTOMALIGN = 0x0020
	TPM_RIGHTBUTTON = 0x0002
	TPM_RETURNCMD   = 0x0100

	IMAGE_ICON      = 1
	LR_LOADFROMFILE = 0x00000010
	LR_DEFAULTSIZE  = 0x00000040

	WM_POWERBROADCAST      = 0x0218
	PBT_APMSUSPEND         = 0x0004
	PBT_APMRESUMESUSPEND   = 0x0007
	PBT_APMRESUMEAUTOMATIC = 0x0012
)

var (
	dllShell32                   = windows.NewLazySystemDLL("shell32.dll")
	dllUser32                    = windows.NewLazySystemDLL("user32.dll")
	procShellNotifyIconW         = dllShell32.NewProc("Shell_NotifyIconW")
	procCreatePopupMenu          = dllUser32.NewProc("CreatePopupMenu")
	procDestroyMenu              = dllUser32.NewProc("DestroyMenu")
	procAppendMenuW              = dllUser32.NewProc("AppendMenuW")
	procTrackPopupMenu           = dllUser32.NewProc("TrackPopupMenu")
	procSetForegroundWindow      = dllUser32.NewProc("SetForegroundWindow")
	procPostMessageW             = dllUser32.NewProc("PostMessageW")
	procLoadImageW               = dllUser32.NewProc("LoadImageW")
	procLoadIconW                = dllUser32.NewProc("LoadIconW")
	procGetCursorPos             = dllUser32.NewProc("GetCursorPos")
	procRegisterClassExW         = dllUser32.NewProc("RegisterClassExW")
	procCreateWindowExW          = dllUser32.NewProc("CreateWindowExW")
	procDefWindowProcW           = dllUser32.NewProc("DefWindowProcW")
	procDestroyWindow            = dllUser32.NewProc("DestroyWindow")
	procGetMessageW              = dllUser32.NewProc("GetMessageW")
	procTranslateMessage         = dllUser32.NewProc("TranslateMessage")
	procDispatchMessageW         = dllUser32.NewProc("DispatchMessageW")
	procPostQuitMessage          = dllUser32.NewProc("PostQuitMessage")
	procSetMenuDefaultItem       = dllUser32.NewProc("SetMenuDefaultItem")
	procCreateIconFromResourceEx = dllUser32.NewProc("CreateIconFromResourceEx")
	procGetSystemMetrics         = dllUser32.NewProc("GetSystemMetrics")
	procGetSystemMetricsForDpi   = dllUser32.NewProc("GetSystemMetricsForDpi")
	procGetDpiForSystem          = dllUser32.NewProc("GetDpiForSystem")
	procRegisterWindowMessageW   = dllUser32.NewProc("RegisterWindowMessageW")

	menuIDCounter uint32 = 1000

	taskbarCreatedMsg  uint32
	taskbarCreatedOnce sync.Once
)

func getTaskbarCreatedMsg() uint32 {
	taskbarCreatedOnce.Do(func() {
		msgName, _ := syscall.UTF16PtrFromString("TaskbarCreated")
		r, _, _ := procRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(msgName)))
		taskbarCreatedMsg = uint32(r)
	})
	return taskbarCreatedMsg
}

type POINT struct {
	X int32
	Y int32
}

type WNDCLASSEXW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     windows.Handle
	HIcon         windows.Handle
	HCursor       windows.Handle
	HbrBackground windows.Handle
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       windows.Handle
}

type MSG struct {
	HWnd    windows.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      POINT
}

// NOTIFYICONDATAW represents the Win32 NOTIFYICONDATA structure for shell notifications.
type NOTIFYICONDATAW struct {
	CbSize           uint32
	HWnd             windows.Handle
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            windows.Handle
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	TimeoutOrVersion uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         windows.GUID
	HBalloonIcon     windows.Handle
}

// MenuItem represents an item in a tray context popup menu.
type MenuItem struct {
	ID          uint32
	Title       string
	Checked     bool
	Disabled    bool
	Default     bool
	IsSeparator bool
	OnClick     func()
	SubMenu     *TrayMenu
}

// TrayMenu represents a container of MenuItem instances.
type TrayMenu struct {
	mu    sync.RWMutex
	Items []*MenuItem
}

// NewTrayMenu creates a new empty TrayMenu.
func NewTrayMenu() *TrayMenu {
	return &TrayMenu{
		Items: make([]*MenuItem, 0),
	}
}

func nextMenuID() uint32 {
	return atomic.AddUint32(&menuIDCounter, 1)
}

// AddItem adds a standard clickable item.
func (m *TrayMenu) AddItem(title string, onClick func()) *MenuItem {
	m.mu.Lock()
	defer m.mu.Unlock()

	item := &MenuItem{
		ID:      nextMenuID(),
		Title:   title,
		OnClick: onClick,
	}
	m.Items = append(m.Items, item)
	return item
}

// AddCheckbox adds a toggleable checkbox item.
func (m *TrayMenu) AddCheckbox(title string, checked bool, onClick func()) *MenuItem {
	m.mu.Lock()
	defer m.mu.Unlock()

	item := &MenuItem{
		ID:      nextMenuID(),
		Title:   title,
		Checked: checked,
		OnClick: onClick,
	}
	m.Items = append(m.Items, item)
	return item
}

// AddSeparator inserts a visual divider.
func (m *TrayMenu) AddSeparator() {
	m.mu.Lock()
	defer m.mu.Unlock()

	item := &MenuItem{
		ID:          nextMenuID(),
		IsSeparator: true,
	}
	m.Items = append(m.Items, item)
}

// AddSubMenu adds a nested menu item.
func (m *TrayMenu) AddSubMenu(title string, sub *TrayMenu) *MenuItem {
	m.mu.Lock()
	defer m.mu.Unlock()

	item := &MenuItem{
		ID:      nextMenuID(),
		Title:   title,
		SubMenu: sub,
	}
	m.Items = append(m.Items, item)
	return item
}

// FindItemByID locates a MenuItem by its unique uint32 ID.
func (m *TrayMenu) FindItemByID(id uint32) *MenuItem {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, item := range m.Items {
		if item.ID == id {
			return item
		}
		if item.SubMenu != nil {
			if found := item.SubMenu.FindItemByID(id); found != nil {
				return found
			}
		}
	}
	return nil
}

// TrayConfig encapsulates configuration for a native taskbar notification icon.
type TrayConfig struct {
	Title         string
	Tooltip       string
	IconPath      string
	IconBytes     []byte
	MenuProvider  func() *TrayMenu
	Menu          *TrayMenu
	OnLeftClick   func()
	OnDoubleClick func()
	OnRightClick  func()
	OnPowerResume func()
}

func getSystemTrayIconSize() (int, int) {
	dpi := uint32(96)
	if procGetDpiForSystem.Find() == nil {
		if r, _, _ := procGetDpiForSystem.Call(); r > 0 {
			dpi = uint32(r)
		}
	}

	cx := 16
	cy := 16
	if procGetSystemMetricsForDpi.Find() == nil && dpi > 0 {
		r1, _, _ := procGetSystemMetricsForDpi.Call(49, uintptr(dpi)) // SM_CXSMICON = 49
		r2, _, _ := procGetSystemMetricsForDpi.Call(50, uintptr(dpi)) // SM_CYSMICON = 50
		if r1 > 0 && r2 > 0 {
			return int(r1), int(r2)
		}
	}

	if procGetSystemMetrics.Find() == nil {
		r1, _, _ := procGetSystemMetrics.Call(49)
		r2, _, _ := procGetSystemMetrics.Call(50)
		if r1 > 0 && r2 > 0 {
			return int(r1), int(r2)
		}
	}

	return cx, cy
}

// LoadIconFromFile loads an HICON from an .ico file on disk.
func LoadIconFromFile(path string) (windows.Handle, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	cx, cy := getSystemTrayIconSize()
	h, _, _ := procLoadImageW.Call(
		0,
		uintptr(unsafe.Pointer(pathPtr)),
		IMAGE_ICON,
		uintptr(cx), uintptr(cy),
		LR_LOADFROMFILE,
	)
	if h != 0 {
		return windows.Handle(h), nil
	}
	h, _, _ = procLoadImageW.Call(
		0,
		uintptr(unsafe.Pointer(pathPtr)),
		IMAGE_ICON,
		0, 0,
		LR_LOADFROMFILE|LR_DEFAULTSIZE,
	)
	if h != 0 {
		return windows.Handle(h), nil
	}
	return 0, fmt.Errorf("LoadImageW failed for %s", path)
}

// LoadIconFromBytes loads an HICON from raw byte data.
func LoadIconFromBytes(b []byte) (windows.Handle, error) {
	if len(b) == 0 {
		return 0, fmt.Errorf("empty icon bytes")
	}

	cx, cy := getSystemTrayIconSize()
	h, _, _ := procCreateIconFromResourceEx.Call(
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(len(b)),
		1, // TRUE for icon
		0x00030000,
		uintptr(cx), uintptr(cy),
		0,
	)
	if h != 0 {
		return windows.Handle(h), nil
	}

	tmp, err := os.CreateTemp("", "srun_tray_*.ico")
	if err != nil {
		return 0, err
	}
	tmpPath := tmp.Name()
	_, _ = tmp.Write(b)
	_ = tmp.Close()
	defer os.Remove(tmpPath)

	return LoadIconFromFile(tmpPath)
}

// BuildWin32PopupMenu constructs a Win32 HMENU popup from TrayMenu.
func BuildWin32PopupMenu(menu *TrayMenu, handlers map[uint32]func()) (windows.Handle, error) {
	if menu == nil {
		return 0, fmt.Errorf("nil menu")
	}

	menu.mu.RLock()
	defer menu.mu.RUnlock()

	hMenu, _, err := procCreatePopupMenu.Call()
	if hMenu == 0 {
		return 0, fmt.Errorf("CreatePopupMenu failed: %w", err)
	}

	for _, item := range menu.Items {
		if item.IsSeparator {
			procAppendMenuW.Call(hMenu, uintptr(MF_SEPARATOR), 0, 0)
			continue
		}

		flags := uintptr(MF_STRING)
		if item.Checked {
			flags |= MF_CHECKED
		}
		if item.Disabled {
			flags |= MF_GRAYED | MF_DISABLED
		}

		if item.SubMenu != nil {
			subHMenu, err := BuildWin32PopupMenu(item.SubMenu, handlers)
			if err == nil && subHMenu != 0 {
				titlePtr, _ := syscall.UTF16PtrFromString(item.Title)
				procAppendMenuW.Call(hMenu, flags|MF_POPUP, uintptr(subHMenu), uintptr(unsafe.Pointer(titlePtr)))
			}
			continue
		}

		titlePtr, _ := syscall.UTF16PtrFromString(item.Title)
		procAppendMenuW.Call(hMenu, flags, uintptr(item.ID), uintptr(unsafe.Pointer(titlePtr)))

		if item.OnClick != nil && handlers != nil {
			handlers[item.ID] = item.OnClick
		}
	}

	return windows.Handle(hMenu), nil
}

// DestroyWin32Menu frees a Win32 HMENU handle.
func DestroyWin32Menu(hMenu windows.Handle) {
	if hMenu != 0 {
		procDestroyMenu.Call(uintptr(hMenu))
	}
}

// ShellNotifyIcon calls Win32 Shell_NotifyIconW with the provided NOTIFYICONDATAW struct.
func ShellNotifyIcon(dwMessage uint32, nid *NOTIFYICONDATAW) (bool, error) {
	if nid == nil {
		return false, fmt.Errorf("nid is nil")
	}
	nid.CbSize = uint32(unsafe.Sizeof(*nid))
	r, _, err := procShellNotifyIconW.Call(uintptr(dwMessage), uintptr(unsafe.Pointer(nid)))
	if r == 0 {
		return false, err
	}
	return true, nil
}

// NativeTray manages the Win32 system notification icon and its message loop.
type NativeTray struct {
	mu            sync.Mutex
	hwnd          windows.Handle
	hIcon         windows.Handle
	nid           NOTIFYICONDATAW
	menuProvider  func() *TrayMenu
	menu          *TrayMenu
	onLeftClick   func()
	onDblClick    func()
	onPowerResume func()
	title         string
	closed        bool
}

// RunNativeTray starts the native Windows taskbar tray icon in a background message loop.
func RunNativeTray(cfg *TrayConfig) (*NativeTray, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil tray config")
	}

	var hIcon windows.Handle

	if len(cfg.IconBytes) > 0 {
		hIcon, _ = LoadIconFromBytes(cfg.IconBytes)
	}
	if hIcon == 0 && cfg.IconPath != "" {
		hIcon, _ = LoadIconFromFile(cfg.IconPath)
	}
	if hIcon == 0 {
		// Fallback to application default icon (32512 = IDI_APPLICATION)
		r, _, _ := procLoadIconW.Call(0, uintptr(32512))
		hIcon = windows.Handle(r)
	}

	tooltip := cfg.Tooltip
	if tooltip == "" {
		tooltip = cfg.Title
	}
	if tooltip == "" {
		tooltip = "校园网登录器"
	}

	tray := &NativeTray{
		hIcon:         hIcon,
		menuProvider:  cfg.MenuProvider,
		menu:          cfg.Menu,
		onLeftClick:   cfg.OnLeftClick,
		onDblClick:    cfg.OnDoubleClick,
		onPowerResume: cfg.OnPowerResume,
		title:         tooltip,
	}

	readyChan := make(chan struct{})
	errChan := make(chan error, 1)

	go tray.runMessageLoop(readyChan, errChan)

	select {
	case <-readyChan:
		return tray, nil
	case err := <-errChan:
		return nil, err
	}
}

func (t *NativeTray) runMessageLoop(readyChan chan struct{}, errChan chan error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	className, _ := syscall.UTF16PtrFromString("SRun_Tray_Message_Class")
	windowName, _ := syscall.UTF16PtrFromString("SRun Tray Message Window")

	wndProcCallback := syscall.NewCallback(func(hwnd windows.Handle, msg uint32, wParam, lParam uintptr) uintptr {
		return t.wndProc(hwnd, msg, wParam, lParam)
	})

	var wc WNDCLASSEXW
	wc.CbSize = uint32(unsafe.Sizeof(wc))
	wc.LpfnWndProc = wndProcCallback
	wc.LpszClassName = className

	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	hwnd, _, err := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowName)),
		0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	)
	if hwnd == 0 {
		errChan <- fmt.Errorf("CreateWindowExW failed for tray: %w", err)
		return
	}

	t.hwnd = windows.Handle(hwnd)

	t.nid.CbSize = uint32(unsafe.Sizeof(t.nid))
	t.nid.HWnd = t.hwnd
	t.nid.UID = 1001
	t.nid.UFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
	t.nid.UCallbackMessage = WM_TRAYICON
	t.nid.HIcon = t.hIcon

	tipUTF16, _ := syscall.UTF16FromString(t.title)
	copy(t.nid.SzTip[:], tipUTF16)

	// Ensure TaskbarCreated message ID is registered
	_ = getTaskbarCreatedMsg()

	// Initial NIM_ADD: on Windows boot, explorer.exe might not have finished creating the notification area.
	// We retry with small pauses up to 5 times.
	for attempt := 0; attempt < 5; attempt++ {
		r, _, _ := procShellNotifyIconW.Call(uintptr(NIM_ADD), uintptr(unsafe.Pointer(&t.nid)))
		if r != 0 {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}

	// Always report ready so parent app doesn't stall; if Explorer initializes later, TaskbarCreated will catch it.
	close(readyChan)

	var msg MSG
	for {
		res, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(res) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

func (t *NativeTray) wndProc(hwnd windows.Handle, msg uint32, wParam, lParam uintptr) uintptr {
	// Re-add tray icon whenever Windows Explorer restarts or finishes initializing the taskbar
	if tbMsg := getTaskbarCreatedMsg(); tbMsg != 0 && msg == tbMsg {
		t.mu.Lock()
		if !t.closed {
			procShellNotifyIconW.Call(uintptr(NIM_ADD), uintptr(unsafe.Pointer(&t.nid)))
		}
		t.mu.Unlock()
		return 0
	}

	switch msg {
	case WM_TRAYICON:
		switch lParam {
		case WM_LBUTTONUP, WM_LBUTTONDBLCLK:
			if t.onDblClick != nil {
				go t.onDblClick()
			} else if t.onLeftClick != nil {
				go t.onLeftClick()
			}
			return 0
		case WM_RBUTTONUP:
			t.showContextMenu()
			return 0
		}
	case WM_DESTROY:
		t.mu.Lock()
		if !t.closed {
			procShellNotifyIconW.Call(uintptr(NIM_DELETE), uintptr(unsafe.Pointer(&t.nid)))
			t.closed = true
		}
		t.mu.Unlock()
		procPostQuitMessage.Call(0)
		return 0
	case WM_POWERBROADCAST:
		if wParam == uintptr(PBT_APMRESUMEAUTOMATIC) || wParam == uintptr(PBT_APMRESUMESUSPEND) {
			if t.onPowerResume != nil {
				go t.onPowerResume()
			}
		}
		return 1
	}
	ret, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
	return ret
}

func (t *NativeTray) showContextMenu() {
	var currentMenu *TrayMenu
	if t.menuProvider != nil {
		currentMenu = t.menuProvider()
	} else {
		currentMenu = t.menu
	}
	if currentMenu == nil {
		return
	}

	var pt POINT
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))

	procSetForegroundWindow.Call(uintptr(t.hwnd))

	handlers := make(map[uint32]func())
	hMenu, err := BuildWin32PopupMenu(currentMenu, handlers)
	if err != nil || hMenu == 0 {
		return
	}
	defer DestroyWin32Menu(hMenu)

	for _, item := range currentMenu.Items {
		if item.Default {
			procSetMenuDefaultItem.Call(uintptr(hMenu), uintptr(item.ID), 0)
			break
		}
	}

	cmd, _, _ := procTrackPopupMenu.Call(
		uintptr(hMenu),
		uintptr(TPM_RIGHTBUTTON|TPM_RETURNCMD),
		uintptr(pt.X),
		uintptr(pt.Y),
		0,
		uintptr(t.hwnd),
		0,
	)

	procPostMessageW.Call(uintptr(t.hwnd), 0, 0, 0)

	if cmd > 0 {
		if fn, exists := handlers[uint32(cmd)]; exists && fn != nil {
			go fn()
		}
	}
}

// Close removes the tray icon from Windows notification area and destroys its window.
func (t *NativeTray) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.closed = true
	procShellNotifyIconW.Call(uintptr(NIM_DELETE), uintptr(unsafe.Pointer(&t.nid)))
	if t.hwnd != 0 {
		procPostMessageW.Call(uintptr(t.hwnd), WM_CLOSE, 0, 0)
	}
}
