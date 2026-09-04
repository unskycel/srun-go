package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/jchv/go-webview2"
	"github.com/jchv/go-webview2/pkg/edge"
	"golang.org/x/sys/windows"

	"srun/internal/domain/event"
	"srun/internal/domain/model"
	platwin "srun/internal/platform/windows"
	"srun/internal/service"
	"srun/internal/ui/bridge"
)

var (
	moduser32                         = windows.NewLazySystemDLL("user32.dll")
	procReleaseCapture                = moduser32.NewProc("ReleaseCapture")
	procSendMessageW                  = moduser32.NewProc("SendMessageW")
	procSetWindowLongW                = moduser32.NewProc("SetWindowLongW")
	procGetWindowLongW                = moduser32.NewProc("GetWindowLongW")
	procSetWindowPos                  = moduser32.NewProc("SetWindowPos")
	procShowWindow                    = moduser32.NewProc("ShowWindow")
	procSetForegroundWindow           = moduser32.NewProc("SetForegroundWindow")
	procGetDpiForWindow               = moduser32.NewProc("GetDpiForWindow")
	procGetDpiForSystem               = moduser32.NewProc("GetDpiForSystem")
	procGetSystemMetrics              = moduser32.NewProc("GetSystemMetrics")
	procLoadImageW                    = moduser32.NewProc("LoadImageW")
	procSetProcessDpiAwarenessContext = moduser32.NewProc("SetProcessDpiAwarenessContext")
	procSetProcessDPIAware            = moduser32.NewProc("SetProcessDPIAware")
	procSetWindowRgn                  = moduser32.NewProc("SetWindowRgn")
	modkernel32                       = windows.NewLazySystemDLL("kernel32.dll")
	procGetModuleHandleW              = modkernel32.NewProc("GetModuleHandleW")
	modgdi32                          = windows.NewLazySystemDLL("gdi32.dll")
	procCreateRoundRectRgn            = modgdi32.NewProc("CreateRoundRectRgn")
	moddwmapi                         = windows.NewLazySystemDLL("dwmapi.dll")
	procDwmSetWindowAttribute         = moddwmapi.NewProc("DwmSetWindowAttribute")
	procDwmExtendFrameIntoClientArea  = moddwmapi.NewProc("DwmExtendFrameIntoClientArea")
)

const (
	WM_NCLBUTTONDOWN       = 0x00A1
	HTCAPTION              = 2
	GWL_STYLE        int32 = -16
	WS_CAPTION             = 0x00C00000
	WS_BORDER              = 0x00800000
	WS_MAXIMIZEBOX         = 0x00010000
	WS_THICKFRAME          = 0x00040000
	SWP_NOSIZE             = 0x0001
	SWP_NOMOVE             = 0x0002
	SWP_NOZORDER           = 0x0004
	SWP_FRAMECHANGED       = 0x0020
	SW_RESTORE             = 9
	SW_MINIMIZE            = 6
	SW_HIDE                = 0
	SW_SHOW                = 5
)

// App manages the desktop client lifecycle.
type App struct {
	mu        sync.Mutex
	cfgSvc    *service.ConfigService
	netSvc    *service.NetworkService
	authSvc   *service.AuthService
	daemonSvc *service.DaemonService
	eventBus  *event.Bus
	bridge    *bridge.BridgeHandler
	server    *AssetServer
	webview   webview2.WebView
	tray      *platwin.NativeTray
	hwnd      windows.HWND
	ctx       context.Context
	cancel    context.CancelFunc
	showChan  chan struct{}
}

func NewApp() *App {
	bus := event.NewBus()
	cfgSvc := service.NewConfigService(bus)
	netSvc := service.NewNetworkService()
	authSvc := service.NewAuthService(cfgSvc, netSvc, bus)
	daemonSvc := service.NewDaemonService(cfgSvc, authSvc)

	ctx, cancel := context.WithCancel(context.Background())

	app := &App{
		cfgSvc:    cfgSvc,
		netSvc:    netSvc,
		authSvc:   authSvc,
		daemonSvc: daemonSvc,
		eventBus:  bus,
		ctx:       ctx,
		cancel:    cancel,
		showChan:  make(chan struct{}, 1),
	}

	app.bridge = bridge.NewBridgeHandler(cfgSvc, netSvc, authSvc, app)
	return app
}

func (a *App) Minimize() {
	a.mu.Lock()
	hwnd := a.hwnd
	a.mu.Unlock()
	if hwnd != 0 {
		procShowWindow.Call(uintptr(hwnd), uintptr(SW_MINIMIZE))
		platwin.TrimWorkingSetDelayed(200 * time.Millisecond)
	}
}

func (a *App) Close() {
	a.mu.Lock()
	wv := a.webview
	a.mu.Unlock()
	if wv != nil {
		wv.Dispatch(func() {
			wv.Destroy()
		})
	}
}

func (a *App) Restore() {
	a.mu.Lock()
	hwnd := a.hwnd
	a.mu.Unlock()
	if hwnd != 0 {
		procShowWindow.Call(uintptr(hwnd), uintptr(SW_RESTORE))
		procSetForegroundWindow.Call(uintptr(hwnd))
		return
	}
	select {
	case a.showChan <- struct{}{}:
	default:
	}
}

func (a *App) Run() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// 0. Enable Windows Per-Monitor V2 High DPI Awareness (Ultra-sharp rendering)
	if procSetProcessDpiAwarenessContext.Find() == nil {
		procSetProcessDpiAwarenessContext.Call(uintptr(^uintptr(3))) // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
	} else if procSetProcessDPIAware.Find() == nil {
		procSetProcessDPIAware.Call()
	}

	// 1. Single Instance Check
	releaseMutex, alreadyRunning, err := platwin.AcquireSingleInstanceMutex(platwin.DefaultMutexName)
	if err == nil {
		defer releaseMutex()
		if alreadyRunning {
			platwin.WakeExistingWindow("校园网登录器")
			return nil
		}
	}

	// 1.1 Register Windows AUMID so Notifications and Settings list this application
	_ = platwin.EnsureAppUserModelIDRegistered("")

	// 2. Start local asset server
	server, err := StartAssetServer()
	if err != nil {
		return fmt.Errorf("failed to start asset server: %w", err)
	}
	a.server = server
	defer server.Close()

	// 3. Start background daemon
	a.daemonSvc.Start(a.ctx)
	defer a.daemonSvc.Stop()

	service.LogInfo("校园网客户端启动就绪 (Windows 高清原生版)")

	// 4. Check & auto-heal auto-start entries if configured, or cleanup stale entries
	cfg := a.cfgSvc.GetConfigCopy()
	if cfg.StartWithWindows {
		if err := platwin.SyncAutoStart(true, ""); err != nil {
			service.LogWarn("自动校准开机自启路径失败: %v", err)
		} else {
			service.LogInfo("已检查并确保开机自启路径与当前可执行文件一致")
		}
	} else if platwin.IsAutoStartEnabled() {
		_ = platwin.SyncAutoStart(false, "")
	}

	// 5. Initialize System Tray
	a.initSystemTray()
	defer func() {
		if a.tray != nil {
			a.tray.Close()
		}
	}()

	// 6. Initial window open unless launched with --no-auto-open
	noAutoOpen := false
	for _, arg := range os.Args {
		if arg == "--no-auto-open" {
			noAutoOpen = true
			break
		}
	}
	// If auto-started in background but user hasn't configured any account,
	// wake the window to guide the user rather than staying completely silent
	if noAutoOpen {
		if strings.TrimSpace(cfg.Username) == "" && len(cfg.Accounts) == 0 {
			service.LogInfo("开机自启检测到尚未配置账号，自动唤起主界面引导配置")
			noAutoOpen = false
		}
	}

	if !noAutoOpen {
		a.showChan <- struct{}{}
	} else {
		platwin.TrimWorkingSetDelayed(500 * time.Millisecond)
	}

	for {
		select {
		case <-a.ctx.Done():
			return nil
		case <-a.showChan:
			a.runWindowLoop(server)
			platwin.TrimWorkingSetDelayed(100 * time.Millisecond)
		}
	}
}

func (a *App) runWindowLoop(server *AssetServer) {
	select {
	case <-a.ctx.Done():
		return
	default:
	}

	// Calculate physical scaled dimensions before creating window
	dpi := uint32(96)
	if procGetDpiForSystem.Find() == nil {
		if r, _, _ := procGetDpiForSystem.Call(); r > 0 {
			dpi = uint32(r)
		}
	}
	baseW := 380
	baseH := 435
	scaledW := int(float64(baseW) * float64(dpi) / 96.0)
	scaledH := int(float64(baseH) * float64(dpi) / 96.0)

	// Inject lightweight, low-memory Chromium arguments for WebView2
	webview2Args := os.Getenv("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS")
	optArgs := "--disable-background-networking " +
		"--disable-component-update " +
		"--disable-domain-reliability " +
		"--disable-sync " +
		"--disable-features=Translate,OptimizationHints,MediaRouter,CalculateNativeWinOcclusion,InterestFeedContentSuggestions " +
		"--renderer-process-limit=1 " +
		"--js-flags=\"--max-old-space-size=64\""
	if webview2Args == "" {
		_ = os.Setenv("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", optArgs)
	} else if !strings.Contains(webview2Args, "--disable-background-networking") {
		_ = os.Setenv("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", webview2Args+" "+optArgs)
	}

	// Ensure isolated, writable WebView2 user data folder in LocalAppData
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		localAppData = os.Getenv("APPDATA")
	}
	dataPath := ""
	if localAppData != "" {
		dataPath = filepath.Join(localAppData, "srun", "webview2_data")
		_ = os.MkdirAll(dataPath, 0755)
	}

	// Initialize WebView2 with exact native physical dimensions from frame 0
	wv := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		DataPath:  dataPath,
		WindowOptions: webview2.WindowOptions{
			Title:  "校园网登录器",
			Width:  uint(scaledW),
			Height: uint(scaledH),
			IconId: 1,
			Center: true,
		},
	})
	if wv == nil {
		return
	}

	a.mu.Lock()
	a.webview = wv
	a.hwnd = windows.HWND(wv.Window())
	a.mu.Unlock()

	defer func() {
		a.mu.Lock()
		a.webview = nil
		a.hwnd = 0
		a.mu.Unlock()
	}()

	// Trim working set after initial loading finishes
	platwin.TrimWorkingSetDelayed(4 * time.Second)

	// Enable true alpha transparency on WebView2 controller
	setWebViewTransparent(wv)

	// Configure frameless window by removing caption and thickframe borders
	style, _, _ := procGetWindowLongW.Call(uintptr(a.hwnd), uintptr(^uintptr(15)))
	style = style &^ uintptr(WS_CAPTION) &^ uintptr(WS_BORDER) &^ uintptr(WS_MAXIMIZEBOX) &^ uintptr(WS_THICKFRAME)
	procSetWindowLongW.Call(uintptr(a.hwnd), uintptr(^uintptr(15)), style)

	// Trigger non-resizing frame update
	procSetWindowPos.Call(uintptr(a.hwnd), 0, 0, 0, 0, 0, uintptr(SWP_NOMOVE|SWP_NOSIZE|SWP_NOZORDER|SWP_FRAMECHANGED))

	// Apply DWM full-frame transparency and desktop drop shadow
	if procDwmExtendFrameIntoClientArea.Find() == nil {
		margins := struct {
			cxLeftWidth    int32
			cxRightWidth   int32
			cyTopHeight    int32
			cyBottomHeight int32
		}{-1, -1, -1, -1}
		procDwmExtendFrameIntoClientArea.Call(uintptr(a.hwnd), uintptr(unsafe.Pointer(&margins)))
	}

	// Apply Windows 11 DWM native rounded corners (DWMWA_WINDOW_CORNER_PREFERENCE = 33, DWMWCP_ROUND = 2)
	if procDwmSetWindowAttribute.Find() == nil {
		pref := int32(2) // DWMWCP_ROUND
		procDwmSetWindowAttribute.Call(uintptr(a.hwnd), uintptr(33), uintptr(unsafe.Pointer(&pref)), uintptr(4))
	}

	// Explicitly assign high-DPI icons to window for taskbar and Alt-Tab switcher
	hInst, _, _ := procGetModuleHandleW.Call(0)
	cxIcon, _, _ := procGetSystemMetrics.Call(11)   // SM_CXICON = 11
	cyIcon, _, _ := procGetSystemMetrics.Call(12)   // SM_CYICON = 12
	cxSmIcon, _, _ := procGetSystemMetrics.Call(49) // SM_CXSMICON = 49
	cySmIcon, _, _ := procGetSystemMetrics.Call(50) // SM_CYSMICON = 50
	hIconBig, _, _ := procLoadImageW.Call(hInst, uintptr(1), 1, cxIcon, cyIcon, 0)
	hIconSm, _, _ := procLoadImageW.Call(hInst, uintptr(1), 1, cxSmIcon, cySmIcon, 0)
	if hIconBig != 0 {
		procSendMessageW.Call(uintptr(a.hwnd), 0x0080, 1, hIconBig) // WM_SETICON, ICON_BIG
	}
	if hIconSm != 0 {
		procSendMessageW.Call(uintptr(a.hwnd), 0x0080, 0, hIconSm) // WM_SETICON, ICON_SMALL
	}

	// Bind IPC handler
	wv.Bind("__go_ipc_call", func(method string, args []any) (any, error) {
		if method == "drag_window" {
			a.mu.Lock()
			hwnd := a.hwnd
			a.mu.Unlock()
			if hwnd != 0 {
				procReleaseCapture.Call()
				procSendMessageW.Call(uintptr(hwnd), uintptr(WM_NCLBUTTONDOWN), uintptr(HTCAPTION), 0)
			}
			return nil, nil
		}
		return a.bridge.Dispatch(method, args)
	})

	// Inject compatibility polyfill
	wv.Init(`
(function() {
    function callGo(method, args) {
        if (typeof window.__go_ipc_call === 'function') {
            return window.__go_ipc_call(method, args || []);
        }
        return Promise.reject(new Error("Go IPC not initialized"));
    }
    window.pywebview = {
        api: {
            get_config: () => callGo('get_config', []),
            set_config: (u, p) => callGo('set_config', [typeof u === 'object' ? u : { username: u, password: p }]),
            get_ip_settings: () => callGo('get_ip_settings', []),
            update_ip_settings: (s) => callGo('update_ip_settings', [s]),
            probe_gateway_ips: (g, s) => callGo('probe_gateway_ips', [g, s]),
            login: (ip) => callGo('login', [ip]),
            logout: (ip) => callGo('logout', [ip]),
            get_online_data: (ip) => callGo('get_online_data', [ip]),
            start_self_service: (ip) => callGo('start_self_service', [ip]),
            reset_config: () => callGo('reset_config', []),
            get_accounts: () => callGo('get_accounts', []),
            switch_account: (u) => callGo('switch_account', [u]),
            save_account: (acc) => callGo('save_account', [acc]),
            delete_account: (u) => callGo('delete_account', [u]),
            set_active_client_ip: (ip) => callGo('set_active_client_ip', [ip]),
            set_active_ip: (ip) => callGo('set_active_ip', [ip]),
            minimize_window: () => callGo('minimize_window', []),
            close_window: () => callGo('close_window', []),
            get_logs: () => callGo('get_logs', []),
            clear_logs: () => callGo('clear_logs', []),
            webbrowser_open: (url) => callGo('webbrowser_open', [url])
        }
    };

    document.addEventListener('mousedown', function(e) {
        if (e.target && e.target.closest && e.target.closest('.pywebview-drag-region')) {
            if (!e.target.closest('button, input, select, a, .toolbar-item, .title-bar-buttons, #minimize-button, #close-button')) {
                callGo('drag_window', []);
            }
        }
    });
})();
`)

	wv.Navigate(server.URL())
	wv.Run()
}

func (a *App) initSystemTray() {
	iconBytes, err := GetAsset("icons/logo.ico")
	if err != nil || len(iconBytes) == 0 {
		iconBytes, _ = GetAsset("icons/journey.ico")
	}

	tray, err := platwin.RunNativeTray(&platwin.TrayConfig{
		Title:         "校园网登录器",
		Tooltip:       "校园网登录器",
		IconBytes:     iconBytes,
		MenuProvider:  a.buildTrayMenu,
		OnLeftClick:   func() { a.Restore() },
		OnDoubleClick: func() { a.Restore() },
		OnPowerResume: func() {
			a.daemonSvc.OnPowerResume()
		},
	})
	if err == nil {
		a.tray = tray
	}
}

func (a *App) buildTrayMenu() *platwin.TrayMenu {
	menu := platwin.NewTrayMenu()

	menu.AddItem("打开主界面", func() {
		a.Restore()
	})
	menu.AddSeparator()

	menu.AddItem("登录", func() {
		go func() {
			_, _ = a.authSvc.Login(context.Background(), "")
			if a.webview != nil {
				a.webview.Dispatch(func() {
					a.webview.Eval("if (typeof updateInfo === 'function') { updateInfo(); }")
				})
			}
		}()
	})

	menu.AddItem("注销", func() {
		go func() {
			_, _ = a.authSvc.Logout(context.Background(), "")
			if a.webview != nil {
				a.webview.Dispatch(func() {
					a.webview.Eval("if (typeof updateInfo === 'function') { updateInfo(); }")
				})
			}
		}()
	})

	menu.AddSeparator()

	menu.AddItem("自服务门户", func() {
		go func() {
			cfg := a.cfgSvc.GetConfigCopy()
			if cfg.SelfService == "" {
				a.Restore()
				if a.webview != nil {
					a.webview.Dispatch(func() {
						a.webview.Eval("showAlert('请先在设置中配置【自服务地址】！'); openSettings();")
					})
				}
				return
			}
			_, _ = a.bridge.StartSelfService(nil)
		}()
	})

	menu.AddItem("运行日志", func() {
		a.Restore()
		a.mu.Lock()
		wv := a.webview
		a.mu.Unlock()
		if wv != nil {
			wv.Dispatch(func() {
				wv.Eval("if (typeof openLogsModal === 'function') { openLogsModal(); }")
			})
		}
	})

	menu.AddSeparator()

	menu.AddItem("退出", func() {
		a.cancel()
		if a.tray != nil {
			a.tray.Close()
		}
		a.mu.Lock()
		wv := a.webview
		a.mu.Unlock()
		if wv != nil {
			wv.Dispatch(func() {
				wv.Destroy()
			})
		}
	})

	return menu
}

func setWebViewTransparent(wv webview2.WebView) {
	if wv == nil {
		return
	}
	defer func() {
		_ = recover()
	}()
	v := reflect.ValueOf(wv)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return
	}
	f := v.FieldByName("browser")
	if !f.IsValid() {
		return
	}
	rf := reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem()
	chromium, ok := rf.Interface().(*edge.Chromium)
	if !ok || chromium == nil {
		return
	}
	ctrl := chromium.GetController()
	if ctrl == nil {
		return
	}
	c2 := ctrl.GetICoreWebView2Controller2()
	if c2 != nil {
		_ = c2.PutDefaultBackgroundColor(edge.COREWEBVIEW2_COLOR{A: 0, R: 0, G: 0, B: 0})
	}
}

func init() {
	_ = json.Marshal
	_ = unsafe.Pointer(nil)
	_ = time.Now
	_ = model.StateOffline
}
