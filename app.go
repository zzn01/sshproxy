package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// app is the set of outbounds built from a config file.
type app struct {
	router  *router
	status  []string    // one line per proxy / group for the banner
	closers []io.Closer // every proxy, closed on exit
	sources []appSource // proxies in name order, for the control panel
	groups  []appSource // groups in name order ("fastest" last)
	byName  map[string]*group
}

// appSource describes one proxy or group for the control panel.
type appSource struct {
	name   string
	kind   string // ssh, fallback, fastest
	detail string
	m      member
}

func (a *app) Close() {
	for _, c := range a.closers {
		c.Close()
	}
}

// startApp connects every SSH server and wires groups and rules. Servers
// that are unreachable keep retrying in the background; login and host key
// errors are returned, since only the user can fix them.
func startApp(ctx context.Context, cfg *appConfig, auth *authenticator, sshCfg sshConfig, hc healthConfig, logf func(string, ...any)) (*app, error) {
	a := &app{}
	status := map[string]string{}
	leaves := map[string]*leaf{outDirect: newLeaf(outDirect, &directOutbound{net.Dialer{Timeout: dialTimeout}}, logf)}
	groups := map[string]*group{}
	sshNames := cfg.proxyNames()
	managers := make([]*sshManager, len(sshNames))
	for i, name := range sshNames {
		p := cfg.Proxies[name]
		target, _ := sshTarget(p.SSH)
		d, err := resolveDest(sshCfg, target, p.Identity, p.Jump)
		if err != nil {
			return nil, fmt.Errorf("proxies.%s: %w", name, err)
		}
		managers[i] = newSSHManager(d, auth, prefixLog(logf, name))
	}

	// Connect concurrently; password prompts are serialized by auth.
	clients := make([]*ssh.Client, len(managers))
	errs := make([]error, len(managers))
	var wg sync.WaitGroup
	for i, m := range managers {
		wg.Go(func() { clients[i], errs[i] = m.connect() })
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil && !errors.As(err, new(*unreachableError)) {
			for _, c := range clients {
				if c != nil {
					c.Close()
				}
			}
			return nil, fmt.Errorf("proxies.%s: %s", sshNames[i], explain(err))
		}
	}
	for i, m := range managers {
		go m.run(clients[i])
		state := "connected"
		if clients[i] == nil {
			state = "unreachable, retrying in background"
		}
		a.closers = append(a.closers, m)
		status[sshNames[i]] = fmt.Sprintf("ssh %s, %s", m.dest, state)
		leaves[sshNames[i]] = newLeaf(sshNames[i], m, logf)
	}
	for _, name := range cfg.proxyNames() {
		a.status = append(a.status, fmt.Sprintf("%-10s %s", name, status[name]))
	}
	var build func(name string) member
	build = func(name string) member {
		if l, ok := leaves[name]; ok {
			return l
		}
		if g, ok := groups[name]; ok {
			return g
		}
		spec := cfg.Groups[name]
		members := make([]member, len(spec.Members))
		for i, m := range spec.Members {
			members[i] = build(m)
		}
		g := newGroup(name, spec.Type, spec.Members, members, logf)
		groups[name] = g
		return g
	}
	// "fastest" is every proxy, lowest latency first. Without rules it
	// receives all traffic.
	names := cfg.proxyNames()
	all := make([]member, len(names))
	for i, n := range names {
		all[i] = build(n)
	}
	groups[outFastest] = newGroup(outFastest, policyFastest, names, all, logf)
	for _, name := range cfg.groupNames() {
		build(name)
		spec := cfg.Groups[name]
		a.status = append(a.status, fmt.Sprintf("%-10s %s: %s", name, spec.Type, strings.Join(spec.Members, ", ")))
	}
	def := ""
	switch {
	case cfg.rules != nil:
	case len(names) == 1:
		def = names[0]
	default:
		def = outFastest
		a.status = append(a.status, fmt.Sprintf("%-10s %s", outFastest, "all traffic, lowest latency of all proxies"))
	}
	for gname, node := range cfg.Pins {
		if g := groups[gname]; g != nil {
			g.setPinned(node)
		}
	}
	a.byName = groups

	for _, name := range cfg.proxyNames() {
		a.sources = append(a.sources, appSource{name: name, kind: "ssh", detail: strings.TrimPrefix(status[name], "ssh "), m: build(name)})
	}
	for _, name := range cfg.groupNames() {
		a.groups = append(a.groups, appSource{name: name, kind: cfg.Groups[name].Type, m: groups[name]})
	}
	if len(names) > 1 {
		a.groups = append(a.groups, appSource{name: outFastest, kind: policyFastest, m: groups[outFastest]})
	}

	// Only leaves that are in a group need health checks. groups is
	// complete from here on, since the monitors read it.
	reevaluate := func() {
		for _, g := range groups {
			g.order()
		}
	}
	monitored := map[string]bool{}
	for _, g := range groups {
		for _, m := range g.members {
			if l, ok := m.(*leaf); ok && l.name != outDirect && !monitored[l.name] {
				monitored[l.name] = true
				l.setOnChange(reevaluate)
				go l.monitor(ctx, hc)
			}
		}
	}

	r := &router{rules: cfg.rules, outbounds: map[string]outbound{}, def: def, logf: logf}
	for name, l := range leaves {
		r.outbounds[name] = l
	}
	for name, g := range groups {
		r.outbounds[name] = g
	}
	a.router = r
	return a, nil
}

func prefixLog(logf func(string, ...any), prefix string) func(string, ...any) {
	return func(format string, args ...any) {
		logf("%s: %s", prefix, fmt.Sprintf(format, args...))
	}
}
