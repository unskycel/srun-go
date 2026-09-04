package windows

import (
	"context"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	dllIPHlpApi              = windows.NewLazySystemDLL("iphlpapi.dll")
	procNotifyAddrChange     = dllIPHlpApi.NewProc("NotifyAddrChange")
	procCancelIPChangeNotify = dllIPHlpApi.NewProc("CancelIPChangeNotify")
)

// ListenNetworkChange returns a read-only channel that emits a signal whenever
// Windows network interfaces, IP addresses, or connection states change.
// The listener stops cleanly when ctx is cancelled.
func ListenNetworkChange(ctx context.Context) <-chan struct{} {
	ch := make(chan struct{}, 1)

	go func() {
		defer close(ch)

		// Create a Win32 event for Overlapped notification
		event, err := windows.CreateEvent(nil, 0, 0, nil)
		if err != nil {
			// Fallback to simple polling if event creation fails
			ticker := time.NewTicker(3 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					select {
					case ch <- struct{}{}:
					default:
					}
				}
			}
		}
		defer windows.CloseHandle(event)

		var handle windows.Handle
		var overlapped windows.Overlapped
		overlapped.HEvent = event

		for {
			if ctx.Err() != nil {
				return
			}

			// Register async notification
			_, _, _ = procNotifyAddrChange.Call(
				uintptr(unsafe.Pointer(&handle)),
				uintptr(unsafe.Pointer(&overlapped)),
			)

			// Wait for event or context cancel
			for {
				s, _ := windows.WaitForSingleObject(event, 300)
				if ctx.Err() != nil {
					procCancelIPChangeNotify.Call(uintptr(unsafe.Pointer(&overlapped)))
					return
				}
				if s == windows.WAIT_OBJECT_0 {
					// Event signaled!
					select {
					case ch <- struct{}{}:
					default:
					}
					// Small debounce sleep before re-registering
					time.Sleep(100 * time.Millisecond)
					break
				}
			}
		}
	}()

	return ch
}

