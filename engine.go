package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// engine runs the proxies of a config file and applies changes made in the
// control panel without restarting the listener.
type engine struct {
	path   string
	auth   *authenticator
	sshCfg sshConfig
	hc     healthConfig
	logs   *logBuffer

	reloadMu sync.Mutex // serializes reloads and config changes
	router   atomic.Pointer[router]

	mu      sync.Mutex // guards the fields below
	cfg     *appConfig
	app     *app
	cancel  context.CancelFunc
	err     error
	loading bool
}

func newEngine(path string, auth *authenticator, sshCfg sshConfig, hc healthConfig, logs *logBuffer) *engine {
	return &engine{path: path, auth: auth, sshCfg: sshCfg, hc: hc, logs: logs}
}

// dial routes through the current config.
func (e *engine) dial(ctx context.Context, addr string) (net.Conn, error) {
	r := e.router.Load()
	if r == nil {
		return nil, errors.New("no proxies yet: open the control panel and add one")
	}
	return r.dial(ctx, addr)
}

// load reads the config file (a missing file is an empty config).
func (e *engine) load() (*appConfig, error) {
	cfg, err := decodeAppConfig(e.path)
	if errors.Is(err, os.ErrNotExist) {
		return &appConfig{path: e.path, Proxies: map[string]proxySource{}}, nil
	}
	if err != nil {
		return nil, err
	}
	if cfg.Proxies == nil {
		cfg.Proxies = map[string]proxySource{}
	}
	return cfg, nil
}

// reload starts the config file's proxies and swaps them in.
func (e *engine) reload() error {
	e.reloadMu.Lock()
	defer e.reloadMu.Unlock()
	cfg, err := e.load()
	if err == nil {
		err = e.start(cfg)
	}
	e.mu.Lock()
	e.err = err
	e.mu.Unlock()
	return err
}

// modify applies change to the config, starts the result and saves it
// only if it starts; otherwise the running setup is kept.
func (e *engine) modify(change func(cfg *appConfig) error) error {
	e.reloadMu.Lock()
	defer e.reloadMu.Unlock()
	cfg, err := e.load()
	if err != nil {
		return err
	}
	if err := change(cfg); err != nil {
		return err
	}
	if err := e.start(cfg); err != nil {
		return err
	}
	e.mu.Lock()
	e.err = nil
	e.mu.Unlock()
	return cfg.save()
}

// start validates cfg, starts its proxies and replaces the running ones.
func (e *engine) start(cfg *appConfig) error {
	e.setLoading(true)
	defer e.setLoading(false)
	var a *app
	var cancel context.CancelFunc
	if len(cfg.Proxies) > 0 {
		if err := cfg.validate(); err != nil {
			return err
		}
		var ctx context.Context
		ctx, cancel = context.WithCancel(context.Background())
		var err error
		if a, err = startApp(ctx, cfg, e.auth, e.sshCfg, e.hc, e.logs.logf); err != nil {
			cancel()
			return err
		}
	}
	if a != nil {
		e.router.Store(a.router)
	} else {
		e.router.Store(nil)
	}
	e.mu.Lock()
	oldApp, oldCancel := e.app, e.cancel
	e.cfg, e.app, e.cancel = cfg, a, cancel
	e.mu.Unlock()
	if oldApp != nil {
		oldCancel()
		oldApp.Close()
	}
	return nil
}

func (e *engine) setLoading(v bool) {
	e.mu.Lock()
	e.loading = v
	e.mu.Unlock()
}

// close stops every proxy.
func (e *engine) close() {
	e.mu.Lock()
	a, cancel := e.app, e.cancel
	e.app, e.cancel = nil, nil
	e.mu.Unlock()
	e.router.Store(nil)
	if a != nil {
		cancel()
		a.Close()
	}
}

// removeSource deletes a proxy and every reference to it.
func (e *engine) removeSource(name string) error {
	return e.modify(func(cfg *appConfig) error {
		if _, ok := cfg.Proxies[name]; !ok {
			return fmt.Errorf("no source named %q", name)
		}
		delete(cfg.Proxies, name)
		removeReferences(cfg, name)
		return nil
	})
}

// removeReferences drops name from groups and rules; groups left empty
// are removed in turn.
func removeReferences(cfg *appConfig, name string) {
	for gname, g := range cfg.Groups {
		if i := slices.Index(g.Members, name); i >= 0 {
			g.Members = slices.Delete(g.Members, i, i+1)
			cfg.Groups[gname] = g
			if len(g.Members) == 0 {
				delete(cfg.Groups, gname)
				removeReferences(cfg, gname)
			}
		}
	}
	cfg.Rules = slices.DeleteFunc(cfg.Rules, func(r ruleLine) bool {
		out, _, _ := strings.Cut(strings.TrimSpace(r.text), " ")
		return strings.EqualFold(out, name)
	})
}

var nameJunk = regexp.MustCompile(`[^a-z0-9_-]+`)

// suggestName derives a config name from an SSH login's host.
func suggestName(src string) string {
	var base string
	target, _ := sshTarget(src)
	if _, host, _, err := parseTarget(target); err == nil {
		base = host
	}
	name := strings.Trim(nameJunk.ReplaceAllString(strings.ToLower(base), "-"), "-")
	if name == "" || name == outDirect || name == outFastest {
		name = "proxy"
	}
	return name
}

func uniqueName(cfg *appConfig, base string) string {
	name := base
	for i := 2; ; i++ {
		_, isProxy := cfg.Proxies[name]
		_, isGroup := cfg.Groups[name]
		if !isProxy && !isGroup {
			return name
		}
		name = fmt.Sprintf("%s-%d", base, i)
	}
}

// logBuffer keeps recent log lines for the control panel and forwards
// them to the standard logger.
type logBuffer struct {
	mu    sync.Mutex
	lines []string
}

const logBufferSize = 200

func (b *logBuffer) logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Print(msg)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lines = append(b.lines, time.Now().Format("15:04:05")+" "+msg)
	if len(b.lines) > logBufferSize {
		b.lines = slices.Clone(b.lines[len(b.lines)-logBufferSize:])
	}
}

func (b *logBuffer) recent() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string{}, b.lines...) // never nil: the panel expects a JSON array
}

// rename gives a proxy or group a new name everywhere it is used.
func (e *engine) rename(from, to string) error {
	to = strings.TrimSpace(to)
	return e.modify(func(cfg *appConfig) error {
		if from == to {
			return nil
		}
		if err := checkName(to, "name"); err != nil {
			return err
		}
		if slices.Contains(cfg.outboundNames(), to) {
			return fmt.Errorf("%q is already used", to)
		}
		if p, ok := cfg.Proxies[from]; ok {
			delete(cfg.Proxies, from)
			cfg.Proxies[to] = p
		} else if g, ok := cfg.Groups[from]; ok {
			delete(cfg.Groups, from)
			cfg.Groups[to] = g
		} else {
			return fmt.Errorf("no source or chain named %q", from)
		}
		for name, g := range cfg.Groups {
			for i, m := range g.Members {
				if m == from {
					g.Members[i] = to
				}
			}
			cfg.Groups[name] = g
		}
		for i, r := range cfg.Rules {
			if out, pat, ok := strings.Cut(strings.TrimSpace(r.text), " "); ok && strings.EqualFold(out, from) {
				cfg.Rules[i].text = to + " " + strings.TrimSpace(pat)
			}
		}
		for g, m := range cfg.Pins {
			if m == from {
				cfg.Pins[g] = to
			}
		}
		if m, ok := cfg.Pins[from]; ok {
			delete(cfg.Pins, from)
			cfg.Pins[to] = m
		}
		return nil
	})
}

// setSSHOptions sets the key file and jump host of an SSH source.
func (e *engine) setSSHOptions(name, identity, jump string) error {
	return e.modify(func(cfg *appConfig) error {
		p, ok := cfg.Proxies[name]
		if !ok || p.SSH == "" {
			return fmt.Errorf("no SSH source named %q", name)
		}
		p.Identity, p.Jump = strings.TrimSpace(identity), strings.TrimSpace(jump)
		cfg.Proxies[name] = p
		return nil
	})
}

// ruleSpec is one routing rule as the control panel edits it.
type ruleSpec struct {
	Match string `json:"match"` // domain or ip
	Value string `json:"value"`
	Out   string `json:"out"`
}

// toRuleSpecs splits config rules into the panel's form: rules before the
// first catch-all, and the catch-all's outbound as the default.
func toRuleSpecs(lines []ruleLine) (rules []ruleSpec, def string) {
	rules = []ruleSpec{}
	for _, l := range lines {
		out, pat, _ := strings.Cut(strings.TrimSpace(l.text), " ")
		pat = strings.TrimSpace(pat)
		if pat == "*" {
			return rules, out
		}
		match := "domain"
		if _, err := netip.ParsePrefix(pat); err == nil {
			match = "ip"
		} else if _, err := netip.ParseAddr(pat); err == nil {
			match = "ip"
		}
		rules = append(rules, ruleSpec{Match: match, Value: pat, Out: out})
	}
	if len(lines) == 0 {
		return rules, outFastest // no rules: everything goes to the fastest
	}
	return rules, outDirect
}

// setRouting replaces the rules. def is where everything else goes.
func (e *engine) setRouting(rules []ruleSpec, def string) error {
	return e.modify(func(cfg *appConfig) error {
		names := cfg.outboundNames()
		cfg.Rules = nil
		for i, r := range rules {
			v := strings.TrimSpace(r.Value)
			_, ipErr := netip.ParsePrefix(v)
			if _, err := netip.ParseAddr(v); err == nil {
				ipErr = nil
			}
			switch {
			case v == "":
				return fmt.Errorf("rule %d: empty %s", i+1, r.Match)
			case r.Match == "ip" && ipErr != nil:
				return fmt.Errorf("rule %d: %q is not an IP address or range like 10.0.0.0/8", i+1, v)
			case r.Match == "domain" && (ipErr == nil || strings.ContainsAny(v, " /:*") && !strings.HasPrefix(v, "*.")):
				return fmt.Errorf("rule %d: %q is not a domain like example.com", i+1, v)
			}
			line := r.Out + " " + v
			if _, _, err := parseRule(line, names); err != nil {
				return fmt.Errorf("rule %d: %v", i+1, err)
			}
			cfg.Rules = append(cfg.Rules, ruleLine{text: line})
		}
		if !slices.Contains(names, def) {
			return fmt.Errorf("unknown destination %q for everything else", def)
		}
		// No rules and the fastest for everything else is the default; keep
		// the config free of a rule that says so.
		if len(cfg.Rules) > 0 || def != outFastest {
			cfg.Rules = append(cfg.Rules, ruleLine{text: def + " *"})
		}
		return nil
	})
}

// putGroup creates or replaces a backup chain.
func (e *engine) putGroup(name, policy string, members []string) error {
	return e.modify(func(cfg *appConfig) error {
		if cfg.Groups == nil {
			cfg.Groups = map[string]groupSpec{}
		}
		if _, isProxy := cfg.Proxies[name]; isProxy {
			return fmt.Errorf("%q is already a source", name)
		}
		cfg.Groups[name] = groupSpec{Type: policy, Members: members}
		if pin, ok := cfg.Pins[name]; ok && !slices.Contains(members, pin) {
			delete(cfg.Pins, name)
		}
		return nil
	})
}

// deleteGroup removes a backup chain and every reference to it.
func (e *engine) deleteGroup(name string) error {
	return e.modify(func(cfg *appConfig) error {
		if _, ok := cfg.Groups[name]; !ok {
			return fmt.Errorf("no chain named %q", name)
		}
		delete(cfg.Groups, name)
		delete(cfg.Pins, name)
		removeReferences(cfg, name)
		return nil
	})
}

// setPin makes a group use member while it works; "" returns to automatic
// choice. It applies to the running setup directly, without reconnecting.
func (e *engine) setPin(group, member string) error {
	e.mu.Lock()
	a := e.app
	e.mu.Unlock()
	if a == nil || a.byName[group] == nil {
		return fmt.Errorf("no group named %q", group)
	}
	err := e.saveSetting(func(cfg *appConfig) {
		if cfg.Pins == nil {
			cfg.Pins = map[string]string{}
		}
		if member == "" {
			delete(cfg.Pins, group)
		} else {
			cfg.Pins[group] = member
		}
	})
	if err == nil {
		a.byName[group].setPinned(member)
	}
	return err
}

// rememberSystemProxy saves whether the system proxy should be on.
func (e *engine) rememberSystemProxy(on bool) error {
	return e.saveSetting(func(cfg *appConfig) { cfg.SystemProxy = on })
}

// saveSetting changes the config file without restarting anything; for
// settings the caller applies to the running setup itself.
func (e *engine) saveSetting(change func(cfg *appConfig)) error {
	e.reloadMu.Lock()
	defer e.reloadMu.Unlock()
	cfg, err := e.load()
	if err != nil {
		return err
	}
	change(cfg)
	if len(cfg.Proxies) > 0 {
		if err := cfg.validate(); err != nil {
			return err
		}
	}
	if err := cfg.save(); err != nil {
		return err
	}
	e.mu.Lock()
	e.cfg = cfg
	e.mu.Unlock()
	return nil
}
