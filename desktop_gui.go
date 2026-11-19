//go:build gui

package main

import (
	"context"
	"log"
	"net/http"
	"runtime"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

// desktopBuild makes a bare double-click (no arguments) start the app.
const desktopBuild = true

const windowName = "main"

// tray is the desktop app: a tray icon and the control panel window. With
// no app, the system can't show a window and the panel opens in the
// browser instead.
type tray struct {
	app *application.App
	p   *panel // set by run before the window loads the panel
}

// newTray creates the app. If sshproxy is already running, it shows that
// one's window and exits: without a tray icon (plain GNOME) launching the
// app again is the only way back to a closed window.
func newTray() *tray {
	t := &tray{}
	if err := windowSupport(); err != nil {
		log.Printf("Can't show the sshproxy window (%v), using the browser instead", err)
		return t
	}
	t.app = application.New(application.Options{
		Name: "sshproxy",
		Assets: application.AssetOptions{
			// In-process requests have no loopback Host; the token still
			// guards the API.
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Host = "localhost"
				t.p.ServeHTTP(w, r)
			}),
		},
		Mac: application.MacOptions{
			ActivationPolicy: application.ActivationPolicyAccessory, // menu bar app, no Dock icon
		},
		SingleInstance: &application.SingleInstanceOptions{
			UniqueID: "io.github.sshproxy",
			OnSecondInstanceLaunch: func(application.SecondInstanceData) {
				if w, ok := application.Get().Window.GetByName(windowName); ok {
					w.Show()
					w.Focus()
				}
			},
		},
	})
	return t
}

// run shows the tray icon and the control panel window until Quit is
// chosen or ctx is done. The window shows the same panel the browser
// would, served in-process. On macOS quitting exits the process without
// returning, so shutdown runs as Wails' shutdown hook.
func (t *tray) run(ctx context.Context, p *panel, firstRun bool, shutdown func()) {
	if t.app == nil {
		runInBrowser(ctx, p, firstRun)
		return
	}
	t.p = p
	app := t.app
	app.OnShutdown(shutdown)

	window := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Name:   windowName,
		Title:  "sshproxy",
		Width:  820,
		Height: 720,
		URL:    "/ui/#" + p.token,
		Hidden: !firstRun,
	})
	// Closing the window keeps sshproxy running in the tray.
	window.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		window.Hide()
		e.Cancel()
	})
	show := func() {
		window.Show()
		window.Focus()
	}
	p.prompt.notify = show // a login needs the user
	p.autostart = app.Autostart

	tray := app.SystemTray.New()
	menu := app.NewMenu()
	menu.Add("Open sshproxy").OnClick(func(*application.Context) { show() })
	menu.AddSeparator()
	proxy := menu.AddCheckbox("System proxy", p.systemProxyOn())
	proxy.OnClick(func(c *application.Context) {
		if err := p.switchSystemProxy(c.ClickedMenuItem().Checked()); err != nil {
			p.e.logs.logf("System proxy: %v", err)
			show()
		}
	})
	startAtLogin, _ := app.Autostart.IsEnabled()
	login := menu.AddCheckbox("Start at login", startAtLogin)
	login.OnClick(func(c *application.Context) {
		if err := p.switchAutostart(c.ClickedMenuItem().Checked()); err != nil {
			p.e.logs.logf("%v", err)
			show()
		}
	})
	menu.AddSeparator()
	// Clearing the system proxy can take seconds with many network
	// services, so disappear first and quit once it is done.
	menu.Add("Quit sshproxy").OnClick(func(*application.Context) {
		window.Hide()
		tray.Hide()
		go func() {
			shutdown()
			app.Quit()
		}()
	})

	if runtime.GOOS == "darwin" {
		tray.SetTemplateIcon(trayIconPNG())
	} else {
		tray.SetIcon(trayIconPNG())
	}
	tray.SetTooltip("sshproxy")
	tray.SetMenu(menu)

	// The panel can switch the system proxy too; keep the checkbox in sync.
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				app.Quit()
				return
			case <-tick.C:
				changed := false
				if on := p.systemProxyOn(); on != proxy.Checked() {
					proxy.SetChecked(on)
					changed = true
				}
				if on, err := app.Autostart.IsEnabled(); err == nil && on != login.Checked() {
					login.SetChecked(on)
					changed = true
				}
				if changed {
					menu.Update()
				}
			}
		}
	}()

	if err := app.Run(); err != nil {
		p.e.logs.logf("Desktop: %v", err)
	}
}
