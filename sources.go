package main

import (
	"cmp"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
)

func existingName(cfg *appConfig, target string) string {
	for n, p := range cfg.Proxies {
		if p.SSH == target {
			return n
		}
	}
	return ""
}

// formDest turns the form into a target string and the destination it
// resolves to. Empty fields are left to ~/.ssh/config (or its defaults), so
// a config alias in the server field works like on the command line.
func (e *engine) formDest(f sshForm) (string, *dest, error) {
	// The server field may hold a whole "user@host:port".
	usr, host, port, err := parseTarget(strings.TrimSpace(f.Host))
	if err != nil {
		return "", nil, errors.New("enter the server address")
	}
	usr, port = cmp.Or(strings.TrimSpace(f.User), usr), cmp.Or(strings.TrimSpace(f.Port), port)
	target := host
	if strings.Contains(host, ":") {
		target = "[" + host + "]" // IPv6
	}
	if port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return "", nil, fmt.Errorf("port %q is not a number from 1 to 65535", port)
		}
		target = net.JoinHostPort(host, port)
	}
	if usr != "" {
		target = usr + "@" + target
	}
	d, err := resolveDest(e.sshCfg, target, strings.TrimSpace(f.Identity), strings.TrimSpace(f.Jump))
	return target, d, err
}

// sshForm is the panel's "SSH server" form.
type sshForm struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	Identity string `json:"identity"`
	Jump     string `json:"jump"`
	Name     string `json:"name"`
}

var errNeedsInput = errors.New("the login needs more input")

// addSSH tries the login with the form's password first, so a wrong
// password or address is reported in the form, then adds the server.
// The password is kept in memory only.
func (e *engine) addSSH(f sshForm) (string, error) {
	host := strings.Trim(strings.TrimSpace(f.Host), "[]")
	if host == "" {
		return "", errors.New("enter the server address")
	}
	target, d, err := e.formDest(f)
	if err != nil {
		return "", err
	}

	// A throwaway authenticator answers password questions from the form
	// and refuses anything else, so nothing pops up during the check.
	probe := newAuthenticator(func(prompt string, echo bool) (string, error) {
		if echo || f.Password == "" {
			return "", errNeedsInput
		}
		return f.Password, nil
	}, e.auth.knownHosts)
	probe.useAgent = e.auth.useAgent
	c, err := newSSHManager(d, probe, func(string, ...any) {}).connect()
	switch {
	case err == nil:
		c.Close()
		e.auth.adopt(probe)
	case errors.Is(err, errNeedsInput):
		// e.g. a key passphrase or a one-time code: the panel will ask.
	default:
		return "", errors.New(explain(err))
	}

	name := strings.TrimSpace(f.Name)
	if name == "" {
		name = suggestName(host)
	}
	src := proxySource{SSH: target, Identity: strings.TrimSpace(f.Identity), Jump: strings.TrimSpace(f.Jump)}
	err = e.modify(func(cfg *appConfig) error {
		if n := existingName(cfg, target); n != "" {
			return fmt.Errorf("already added as %q", n)
		}
		if err := checkName(name, "name"); err != nil {
			return err
		}
		if slices.Contains(cfg.outboundNames(), name) {
			return fmt.Errorf("name %q is already used", name)
		}
		cfg.Proxies[name] = src
		return nil
	})
	return name, err
}
