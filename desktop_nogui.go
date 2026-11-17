//go:build !gui

package main

import (
	"context"
	"fmt"
)

const desktopBuild = false

// tray has no window in this build.
type tray struct{}

func newTray() *tray { return &tray{} }

// run opens the panel in the browser on first run, prints its address and
// waits.
func (*tray) run(ctx context.Context, p *panel, firstRun bool, _ func()) {
	p.prompt.notify = func() { openBrowser(p.url()) } // a login needs the user
	if firstRun {
		openBrowser(p.url())
	}
	fmt.Printf("Control panel: %s\n  (Ctrl+C to quit)\n", p.url())
	<-ctx.Done()
}
