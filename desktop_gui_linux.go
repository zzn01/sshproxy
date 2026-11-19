//go:build gui && linux

package main

import (
	"errors"
	"os"

	"github.com/ebitengine/purego"
)

// windowSupport reports why the app window can't be shown, or nil. Wails
// exits when the GTK 4 or WebKitGTK 6.0 libraries are missing, so this runs
// first and sshproxy falls back to the browser instead.
func windowSupport() error {
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return errors.New("no display")
	}
	for _, lib := range []string{"libgtk-4.so.1", "libwebkitgtk-6.0.so.4"} {
		if _, err := purego.Dlopen(lib, purego.RTLD_NOW|purego.RTLD_GLOBAL); err != nil {
			return errors.New(lib + " is not installed")
		}
	}
	return nil
}
