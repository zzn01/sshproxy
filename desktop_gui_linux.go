//go:build gui && linux

package main

import (
	"errors"
	"os"

	"github.com/ebitengine/purego"
	"github.com/godbus/dbus/v5"
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

// hasTray reports whether the desktop shows tray icons. Plain GNOME (e.g.
// Fedora) doesn't without the AppIndicator extension.
func hasTray() bool {
	conn, err := dbus.SessionBus()
	if err != nil {
		return false
	}
	var ok bool
	err = conn.BusObject().Call("org.freedesktop.DBus.NameHasOwner", 0, "org.kde.StatusNotifierWatcher").Store(&ok)
	return err == nil && ok
}
