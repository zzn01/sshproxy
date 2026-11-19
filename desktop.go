package main

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"log"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
)

// runGUI runs the control panel mode: engine, panel and (in desktop
// builds) the tray icon.
func runGUI(ctx context.Context, path, listen string) error {
	logs := &logBuffer{}
	if desktopBuild {
		logToFile()
	}
	// Before taking the port, so that launching the desktop app again
	// hands over to the running one instead of failing.
	t := newTray()
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	prompter := &uiPrompter{}
	auth := newAuthenticator(prompter.prompt, filepath.Join(home, ".ssh", "known_hosts"))
	e := newEngine(path, auth, loadSSHConfig(), defaultHealth, logs)

	cfg, err := e.load()
	if err != nil {
		return err
	}
	ln, err := listenLocal(cmp.Or(listen, cfg.Listen))
	if err != nil {
		return err
	}
	defer ln.Close()
	p := newPanel(e, ln.Addr().String(), prompter)

	// A crash can leave the OS pointing at a proxy that no longer runs,
	// which breaks the user's internet; undo that first.
	if systemProxyIsSet(p.addr) {
		clearSystemProxy(p.addr)
		logs.logf("Cleared a system proxy setting left over from a previous run")
	}
	if cfg.SystemProxy {
		if err := p.applySystemProxy(true); err != nil {
			logs.logf("System proxy: %v", err)
		}
	}
	go serveProxy(ln, e.dial, p)
	go func() {
		if err := e.reload(); err != nil {
			logs.logf("Config: %v", err)
		}
	}()
	// Quitting from the tray ends the process inside t.run on some
	// platforms, so t.run also calls shutdown on its way out.
	shutdown := sync.OnceFunc(func() {
		if p.systemProxyOn() {
			clearSystemProxy(p.addr)
		}
		e.close()
	})
	// First run: show where to paste.
	t.run(ctx, p, len(cfg.Proxies) == 0, shutdown)
	shutdown()
	return nil
}

// logToFile also writes logs to a file, since a desktop app has no
// terminal to show them.
func logToFile() {
	dir, err := os.UserCacheDir()
	if err != nil {
		return
	}
	dir = filepath.Join(dir, "sshproxy")
	if os.MkdirAll(dir, 0o700) != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, "sshproxy.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	// The file first: in a Windows GUI app writes to stderr fail, and
	// MultiWriter stops at the first error.
	log.SetOutput(io.MultiWriter(f, os.Stderr))
}

// runInBrowser serves the panel without a window: it opens the panel in the
// browser on first run and whenever a login needs the user, prints its
// address and waits.
func runInBrowser(ctx context.Context, p *panel, firstRun bool) {
	p.prompt.notify = func() { openBrowser(p.url()) }
	if firstRun {
		openBrowser(p.url())
	}
	fmt.Printf("Control panel: %s\n  (Ctrl+C to quit)\n", p.url())
	<-ctx.Done()
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Open %s in your browser\n", url)
		return
	}
	go cmd.Wait()
}

// trayIconPNG draws the tray icon: a ring with a dot, black on
// transparent, which macOS recolors as a template image.
func trayIconPNG() []byte {
	const size = 44
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	c := float64(size-1) / 2
	for y := range size {
		for x := range size {
			d := math.Hypot(float64(x)-c, float64(y)-c)
			// ring between 15 and 20, dot inside 7, with 1px anti-aliasing
			a := max(edge(d, 15, 20), edge(d, -1, 7))
			img.SetNRGBA(x, y, color.NRGBA{A: uint8(a * 255)})
		}
	}
	var buf bytes.Buffer
	png.Encode(&buf, img)
	return buf.Bytes()
}

// edge is 1 for lo <= d <= hi, fading out over 1px on both sides.
func edge(d, lo, hi float64) float64 {
	return math.Max(0, math.Min(1, math.Min(d-lo+0.5, hi-d+0.5)))
}

var errGUIArgs = errors.New("-i, -J and -rules don't apply to the control panel; manage sources in the panel instead")
