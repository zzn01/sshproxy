package main

import (
	"errors"
	"net"
	"strings"
)

// Linux has no single system proxy: GNOME-based desktops (and the
// browsers running there) read gsettings, KDE Plasma reads kioslaverc.
// linuxDesktops sets both, so it works whichever one the user runs. It
// lives outside the linux-only file so its commands can be tested
// anywhere.
type linuxDesktops struct {
	run  func(name string, args ...string) (string, error) // runs a command, returns its output
	look func(name string) (string, error)                 // exec.LookPath
}

// errNoDesktop means neither GNOME nor KDE settings are available.
var errNoDesktop = errors.New("couldn't find GNOME or KDE proxy settings on this system")

func (l linuxDesktops) set(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	var errs []error
	ok := false
	if l.has("gsettings") {
		if err := l.setGNOME(host, port); err != nil {
			errs = append(errs, err)
		} else {
			ok = true
		}
	}
	if kw := l.kwrite(); kw != "" {
		if err := l.setKDE(kw, host, port); err != nil {
			errs = append(errs, err)
		} else {
			ok = true
		}
	}
	switch {
	case ok:
		return nil
	case len(errs) > 0:
		return errors.Join(errs...)
	}
	return errNoDesktop
}

func (l linuxDesktops) isSet(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	return err == nil && (l.gnomeIsSet(host, port) || l.kdeIsSet(host, port))
}

// clear turns off settings that point at addr, leaving any other proxy the
// user configured alone.
func (l linuxDesktops) clear(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	var errs []error
	if l.gnomeIsSet(host, port) {
		if _, err := l.run("gsettings", "set", "org.gnome.system.proxy", "mode", "none"); err != nil {
			errs = append(errs, err)
		}
	}
	if l.kdeIsSet(host, port) {
		if _, err := l.run(l.kwrite(), "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "0"); err != nil {
			errs = append(errs, err)
		}
		l.notifyKDE()
	}
	return errors.Join(errs...)
}

func (l linuxDesktops) has(name string) bool {
	_, err := l.look(name)
	return err == nil
}

// GNOME (also Ubuntu, Cinnamon, Budgie, Pantheon, ...).

func (l linuxDesktops) setGNOME(host, port string) error {
	for _, kind := range []string{"http", "https", "socks"} {
		if _, err := l.run("gsettings", "set", "org.gnome.system.proxy."+kind, "host", host); err != nil {
			return err
		}
		if _, err := l.run("gsettings", "set", "org.gnome.system.proxy."+kind, "port", port); err != nil {
			return err
		}
	}
	_, err := l.run("gsettings", "set", "org.gnome.system.proxy", "mode", "manual")
	return err
}

func (l linuxDesktops) gnomeIsSet(host, port string) bool {
	if !l.has("gsettings") {
		return false
	}
	get := func(args ...string) string {
		out, _ := l.run("gsettings", append([]string{"get"}, args...)...)
		return strings.Trim(strings.TrimSpace(out), "'")
	}
	return get("org.gnome.system.proxy", "mode") == "manual" &&
		get("org.gnome.system.proxy.http", "host") == host &&
		get("org.gnome.system.proxy.http", "port") == port
}

// KDE Plasma 5 and 6.

// kwrite returns the kwriteconfig command of the installed Plasma, or "".
func (l linuxDesktops) kwrite() string {
	for _, name := range []string{"kwriteconfig6", "kwriteconfig5"} {
		if l.has(name) {
			return name
		}
	}
	return ""
}

func (l linuxDesktops) setKDE(kwrite, host, port string) error {
	for key, value := range map[string]string{
		// KDE writes proxies as "scheme://host port".
		"httpProxy":  "http://" + host + " " + port,
		"httpsProxy": "http://" + host + " " + port,
		"socksProxy": "socks://" + host + " " + port,
		"NoProxyFor": "localhost,127.0.0.1,::1",
		"ProxyType":  "1", // manual
	} {
		if _, err := l.run(kwrite, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", key, value); err != nil {
			return err
		}
	}
	l.notifyKDE()
	return nil
}

func (l linuxDesktops) kdeIsSet(host, port string) bool {
	kw := l.kwrite()
	if kw == "" {
		return false
	}
	read := strings.Replace(kw, "kwriteconfig", "kreadconfig", 1)
	get := func(key string) string {
		out, _ := l.run(read, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", key)
		return strings.TrimSpace(out)
	}
	return get("ProxyType") == "1" && get("httpProxy") == "http://"+host+" "+port
}

// notifyKDE tells running KDE programs to reload the proxy settings.
func (l linuxDesktops) notifyKDE() {
	if l.has("dbus-send") {
		l.run("dbus-send", "--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:")
	}
}
