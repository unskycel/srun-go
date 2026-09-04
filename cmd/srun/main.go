package main

//go:generate rsrc -manifest ../../srun.manifest -ico ../../logo.ico -arch amd64 -o rsrc_windows_amd64.syso
//go:generate rsrc -manifest ../../srun.manifest -ico ../../logo.ico -arch 386 -o rsrc_windows_386.syso

import (
	"os"

	"srun/internal/ui"
)

// ParseStartupFlags returns true if --no-auto-open is passed in args.
func ParseStartupFlags(args []string) bool {
	return len(args) > 1 && args[1] == "--no-auto-open"
}

func main() {
	app := ui.NewApp()
	if err := app.Run(); err != nil {
		os.Exit(1)
	}
}
