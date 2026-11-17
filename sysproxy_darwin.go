package main

import (
	"errors"
	"net"
	"os/exec"
	"strings"
)

// runCmd runs a command and returns its combined output; tests replace it.
var runCmd = func(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

// networkServices lists enabled macOS network services.
func networkServices() ([]string, error) {
	out, err := runCmd("networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	var services []string
	for i, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if i == 0 || line == "" || strings.HasPrefix(line, "*") {
			continue // header, blank, or disabled service
		}
		services = append(services, line)
	}
	return services, nil
}

// setSystemProxy points the HTTP, HTTPS and SOCKS proxies of every enabled
// network service at addr. Services that refuse (some VPNs) are skipped.
func setSystemProxy(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	services, err := networkServices()
	if err != nil {
		return err
	}
	ok := 0
	var lastErr error
	for _, svc := range services {
		if _, err := runCmd("networksetup", "-setwebproxy", svc, host, port); err != nil {
			lastErr = err
			continue
		}
		runCmd("networksetup", "-setsecurewebproxy", svc, host, port)
		runCmd("networksetup", "-setsocksfirewallproxy", svc, host, port)
		ok++
	}
	if ok == 0 {
		return errors.Join(errors.New("no network service accepted the proxy setting"), lastErr)
	}
	return nil
}

// pointsAt reports whether networksetup -get*proxy output is an enabled
// proxy at addr.
func pointsAt(out, addr string) bool {
	var enabled bool
	var host, port string
	for _, line := range strings.Split(out, "\n") {
		k, v, _ := strings.Cut(line, ":")
		switch strings.TrimSpace(k) {
		case "Enabled":
			enabled = strings.TrimSpace(v) == "Yes"
		case "Server":
			host = strings.TrimSpace(v)
		case "Port":
			port = strings.TrimSpace(v)
		}
	}
	return enabled && net.JoinHostPort(host, port) == addr
}

// systemProxyIsSet reports whether any service's web proxy points at addr.
func systemProxyIsSet(addr string) bool {
	services, _ := networkServices()
	for _, svc := range services {
		if out, err := runCmd("networksetup", "-getwebproxy", svc); err == nil && pointsAt(out, addr) {
			return true
		}
	}
	return false
}

// clearSystemProxy turns off proxy settings that point at addr, leaving
// anything else the user configured alone.
func clearSystemProxy(addr string) error {
	services, err := networkServices()
	if err != nil {
		return err
	}
	for _, svc := range services {
		for _, kind := range []string{"webproxy", "securewebproxy", "socksfirewallproxy"} {
			if out, err := runCmd("networksetup", "-get"+kind, svc); err == nil && pointsAt(out, addr) {
				runCmd("networksetup", "-set"+kind+"state", svc, "off")
			}
		}
	}
	return nil
}
