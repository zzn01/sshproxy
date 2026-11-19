//go:build gui && !linux

package main

// windowSupport reports why the app window can't be shown, or nil.
func windowSupport() error { return nil }

// hasTray reports whether the desktop shows tray icons.
func hasTray() bool { return true }
