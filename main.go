// Command sshproxy turns SSH logins into one local HTTP/HTTPS/SOCKS5 proxy
// with rule-based routing and failover.
package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

const defaultListen = "127.0.0.1:7890"

func main() {
	listen := flag.String("l", "", "local listen address (default "+defaultListen+")")
	configFile := flag.String("c", "", "config file (default "+defaultConfigPath()+")")
	identity := flag.String("i", "", "private key file")
	jump := flag.String("J", "", "jump host, [user@]host[:port]")
	rulesFile := flag.String("rules", "", "routing rules file (default: everything goes through SSH)")
	gui := flag.Bool("gui", false, "run the control panel (with a tray icon in desktop builds)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n"+
			"  sshproxy [flags] [user@]host[:port]   one SSH server, e.g. sshproxy root@1.2.3.4\n"+
			"  sshproxy [-c config.yaml] [-l addr]   several SSH servers from a config file\n"+
			"  sshproxy -gui                         control panel in the browser\n\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	// Allow flags after the destination too: sshproxy host -l :8080
	var target string
	if flag.NArg() > 0 {
		target = flag.Arg(0)
		flag.CommandLine.Parse(flag.Args()[1:])
		if flag.NArg() > 0 {
			flag.Usage()
			os.Exit(2)
		}
	}

	log.SetFlags(log.Ltime)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch {
	case (*gui || desktopBuild) && target == "":
		if *identity != "" || *jump != "" || *rulesFile != "" {
			err = errGUIArgs
		} else {
			err = runGUI(ctx, cmp.Or(*configFile, defaultConfigPath()), *listen)
		}
	case target != "" && *configFile != "":
		err = errors.New("give either a destination or -c, not both")
	case strings.Contains(target, "://") && !strings.HasPrefix(target, "ssh://"):
		err = errors.New(unsupportedSource(target))
	case target != "":
		target, _ = sshTarget(target)
		err = runSingle(ctx, target, *listen, *identity, *jump, *rulesFile)
	case *identity != "" || *jump != "" || *rulesFile != "":
		err = errors.New("-i, -J and -rules only work with a destination; use the config file instead")
	default:
		path := cmp.Or(*configFile, defaultConfigPath())
		if _, statErr := os.Stat(path); *configFile == "" && errors.Is(statErr, os.ErrNotExist) {
			flag.Usage()
			fmt.Fprintf(os.Stderr, "\nNo config file at %s. Example:\n\n%s", path, exampleConfig)
			os.Exit(2)
		}
		var cfg *appConfig
		if cfg, err = loadAppConfig(path); err == nil {
			fmt.Fprintf(os.Stderr, "Config: %s\n", path)
			err = runConfig(ctx, cfg, *listen)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func newTerminalAuth() (*authenticator, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return newAuthenticator(terminalPrompt(), filepath.Join(home, ".ssh", "known_hosts")), nil
}

// loadRulesFile reads an optional rules file whose rules may name out or
// direct.
func loadRulesFile(path, out string) (*ruleSet, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseRules(f, path, []string{out, outDirect})
}

func printRules(rs *ruleSet, rulesFile, via string) {
	if rs != nil {
		fmt.Printf("  Rules:  %s (%d rules, unmatched go direct)\n", rulesFile, rs.len())
	} else {
		fmt.Printf("  Rules:  none, everything goes through %s\n", via)
	}
}

// runSingle serves one SSH server, as given on the command line.
func runSingle(ctx context.Context, target, listen, identity, jump, rulesFile string) error {
	rs, err := loadRulesFile(rulesFile, outSSH)
	if err != nil {
		return err
	}
	if identity != "" {
		if _, err := os.Stat(identity); err != nil {
			return fmt.Errorf("key file: %w", err)
		}
	}
	d, err := resolveDest(loadSSHConfig(), target, identity, jump)
	if err != nil {
		return err
	}
	auth, err := newTerminalAuth()
	if err != nil {
		return err
	}
	m := newSSHManager(d, auth, log.Printf)

	fmt.Fprintf(os.Stderr, "Connecting to %s...\n", d)
	c, err := m.connectWithRetry(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return errors.New(explain(err))
	}
	ln, err := listenLocal(listen)
	if err != nil {
		c.Close()
		return err
	}
	go m.run(c)

	fmt.Printf("Connected to %s\n", d.Host)
	printProxyHint(ln.Addr().String())
	printRules(rs, rulesFile, d.Host)
	fmt.Println("  Reconnects automatically. Press Ctrl+C to quit.")

	r := &router{
		rules: rs,
		outbounds: map[string]outbound{
			outSSH:    m,
			outDirect: &directOutbound{net.Dialer{Timeout: dialTimeout}},
		},
		def:  outSSH,
		logf: log.Printf,
	}
	return serve(ctx, ln, r, func() { m.Close() })
}

// runConfig serves the proxies, groups and rules of a config.
func runConfig(ctx context.Context, cfg *appConfig, listen string) error {
	auth, err := newTerminalAuth()
	if err != nil {
		return err
	}
	a, err := startApp(ctx, cfg, auth, loadSSHConfig(), defaultHealth, log.Printf)
	if err != nil {
		return err
	}
	ln, err := listenLocal(cmp.Or(listen, cfg.Listen))
	if err != nil {
		a.Close()
		return err
	}
	for _, s := range a.status {
		fmt.Println("  " + s)
	}
	printProxyHint(ln.Addr().String())
	if cfg.rules != nil {
		fmt.Printf("  Rules:  %d rules, unmatched go direct\n", cfg.rules.len())
	}
	fmt.Println("  Fails over and reconnects automatically. Press Ctrl+C to quit.")
	return serve(ctx, ln, a.router, a.Close)
}

// serve runs the proxy until ctx is done, then calls closeAll.
func serve(ctx context.Context, ln net.Listener, r *router, closeAll func()) error {
	go func() {
		<-ctx.Done()
		ln.Close()
		closeAll()
	}()
	err := serveProxy(ln, r.dial, nil)
	if ctx.Err() != nil {
		fmt.Fprintln(os.Stderr, "Bye.")
		return nil
	}
	return err
}

// listenLocal listens on addr, or on the first free port from 7890 to 7900
// when no address was given.
func listenLocal(addr string) (net.Listener, error) {
	if addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("can't listen on %s (%v); pick another address with -l", addr, err)
		}
		return ln, nil
	}
	host, portStr, _ := net.SplitHostPort(defaultListen)
	port, _ := strconv.Atoi(portStr)
	var lastErr error
	for p := port; p <= port+10; p++ {
		ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(p)))
		if err == nil {
			return ln, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("no free local port between %d and %d (%v); pick one with -l", port, port+10, lastErr)
}

func printProxyHint(addr string) {
	proxy := "http://" + addr
	fmt.Printf("  Proxy:  %s  (HTTP, HTTPS and SOCKS5 on the same port)\n", proxy)
	if runtime.GOOS == "windows" {
		fmt.Printf("  Shell:  $env:HTTP_PROXY=\"%s\"; $env:HTTPS_PROXY=\"%s\"   (PowerShell)\n", proxy, proxy)
	} else {
		fmt.Printf("  Shell:  export http_proxy=%s https_proxy=%s\n", proxy, proxy)
	}
}
