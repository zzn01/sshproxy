//go:build !gui

package main

import "context"

const desktopBuild = false

// tray has no window in this build.
type tray struct{}

func newTray() *tray { return &tray{} }

func (*tray) run(ctx context.Context, p *panel, firstRun bool, _ func()) {
	runInBrowser(ctx, p, firstRun)
}
