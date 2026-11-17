package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

const exampleConfig = `# sshproxy config
proxies:                     # SSH servers
  hk:     root@1.2.3.4       # SSH login (or an alias from ~/.ssh/config)
  office: { ssh: me@office.example.com, identity: ~/.ssh/work, jump: bastion }

groups:                      # optional: backup chains
  main: [hk, office]         # use hk; if it fails, office

rules:                       # first match wins, unmatched go direct
  - office  corp.example.com
  - office  10.0.0.0/8
  - main    *
`

// appConfig is the config file.
type appConfig struct {
	Listen  string                 `yaml:"listen,omitempty"`
	Proxies map[string]proxySource `yaml:"proxies"`
	Groups  map[string]groupSpec   `yaml:"groups,omitempty"`
	Rules   []ruleLine             `yaml:"rules,omitempty"`
	Pins    map[string]string      `yaml:"pins,omitempty"` // group -> member chosen by hand
	// SystemProxy remembers that the desktop app should point the OS
	// proxy setting at sshproxy whenever it runs.
	SystemProxy bool `yaml:"system_proxy,omitempty"`

	path  string
	rules *ruleSet
}

// proxySource is one SSH server: a login, optionally with a key and a jump
// host.
type proxySource struct {
	SSH      string `yaml:"ssh"`
	Identity string `yaml:"identity"`
	Jump     string `yaml:"jump"`
	line     int
}

func (p *proxySource) UnmarshalYAML(n *yaml.Node) error {
	p.line = n.Line
	switch n.Kind {
	case yaml.ScalarNode:
		p.SSH = n.Value
		return nil
	case yaml.MappingNode:
		type plain proxySource
		if err := decodeStrict(n, (*plain)(p), "ssh", "identity", "jump"); err != nil {
			return err
		}
		p.line = n.Line
		return nil
	}
	return fmt.Errorf("line %d: want an SSH login, or { ssh: ... }", n.Line)
}

// groupSpec is a group: a member list (fallback) or {type, members}.
type groupSpec struct {
	Type    string   `yaml:"type"`
	Members []string `yaml:"members"`
	line    int
}

func (g *groupSpec) UnmarshalYAML(n *yaml.Node) error {
	g.line = n.Line
	switch n.Kind {
	case yaml.SequenceNode:
		g.Type = policyFallback
		return n.Decode(&g.Members)
	case yaml.MappingNode:
		type plain groupSpec
		if err := decodeStrict(n, (*plain)(g), "type", "members"); err != nil {
			return err
		}
		g.line = n.Line
		if g.Type == "" {
			g.Type = policyFallback
		}
		return nil
	}
	return fmt.Errorf("line %d: want [member, ...] or { type: ..., members: [...] }", n.Line)
}

type ruleLine struct {
	text string
	line int
}

func (r *ruleLine) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: want a rule like \"main *\"", n.Line)
	}
	r.text, r.line = n.Value, n.Line
	return nil
}

// decodeStrict decodes a mapping node, rejecting keys not in allowed.
func decodeStrict(n *yaml.Node, v any, allowed ...string) error {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if k := n.Content[i]; !slices.Contains(allowed, k.Value) {
			return fmt.Errorf("line %d: unknown key %q, want one of: %s", k.Line, k.Value, strings.Join(allowed, ", "))
		}
	}
	return n.Decode(v)
}

func defaultConfigPath() string {
	if runtime.GOOS == "windows" {
		dir, _ := os.UserConfigDir()
		return filepath.Join(dir, "sshproxy", "config.yaml")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "sshproxy", "config.yaml")
}

var validName = regexp.MustCompile(`^[a-z0-9_-]+$`)

// loadAppConfig reads and validates the config file at path.
func loadAppConfig(path string) (*appConfig, error) {
	cfg, err := decodeAppConfig(path)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// decodeAppConfig parses the config file at path without validating it.
func decodeAppConfig(path string) (*appConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cfg := &appConfig{path: path}
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %v", path, strings.TrimPrefix(err.Error(), "yaml: "))
	}
	return cfg, nil
}

// save writes the config to its path. Comments are not preserved.
func (c *appConfig) save() error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

func (p proxySource) MarshalYAML() (any, error) {
	if p.Identity == "" && p.Jump == "" {
		return p.SSH, nil
	}
	type plain struct {
		SSH      string `yaml:"ssh"`
		Identity string `yaml:"identity,omitempty"`
		Jump     string `yaml:"jump,omitempty"`
	}
	return plain{p.SSH, p.Identity, p.Jump}, nil
}

func (g groupSpec) MarshalYAML() (any, error) {
	if g.Type == policyFallback {
		return g.Members, nil
	}
	type plain struct {
		Type    string   `yaml:"type"`
		Members []string `yaml:"members,flow"`
	}
	return plain{g.Type, g.Members}, nil
}

func (r ruleLine) MarshalYAML() (any, error) { return r.text, nil }

func (c *appConfig) validate() error {
	if len(c.Proxies) == 0 {
		return errors.New("no proxies; add one under \"proxies:\"")
	}
	for _, name := range c.proxyNames() {
		p := c.Proxies[name]
		if err := checkName(name, "proxies"); err != nil {
			return fmt.Errorf("line %d: %w", p.line, err)
		}
		target, ok := sshTarget(p.SSH)
		if !ok {
			return fmt.Errorf("line %d: proxies.%s: %s", p.line, name, unsupportedSource(p.SSH))
		}
		if target == "" {
			return fmt.Errorf("line %d: proxies.%s: empty", p.line, name)
		}
	}
	for _, name := range c.groupNames() {
		g := c.Groups[name]
		if err := checkName(name, "groups"); err != nil {
			return fmt.Errorf("line %d: %w", g.line, err)
		}
		if _, dup := c.Proxies[name]; dup {
			return fmt.Errorf("line %d: groups.%s: a proxy has the same name", g.line, name)
		}
		if g.Type != policyFallback && g.Type != policyFastest {
			return fmt.Errorf("line %d: groups.%s: unknown type %q, want fallback or fastest", g.line, name, g.Type)
		}
		if len(g.Members) == 0 {
			return fmt.Errorf("line %d: groups.%s: no members", g.line, name)
		}
		for _, m := range g.Members {
			if !slices.Contains(c.outboundNames(), m) {
				return fmt.Errorf("line %d: groups.%s: unknown member %q", g.line, name, m)
			}
		}
	}
	for gname, member := range c.Pins {
		g, isGroup := c.Groups[gname]
		switch {
		case isGroup && !slices.Contains(g.Members, member):
			return fmt.Errorf("pins.%s: %q is not a member", gname, member)
		case !isGroup && gname != outFastest:
			return fmt.Errorf("pins.%s: no such group", gname)
		}
	}
	if cycle := c.findCycle(); cycle != nil {
		return fmt.Errorf("groups contain each other: %s", strings.Join(cycle, " -> "))
	}

	var rs []rule
	for _, r := range c.Rules {
		ru, ok, err := parseRule(r.text, c.outboundNames())
		if err != nil {
			return fmt.Errorf("line %d: %w", r.line, err)
		}
		if ok {
			rs = append(rs, ru)
		}
	}
	if len(rs) > 0 {
		c.rules = newRuleSet(rs)
	}
	return nil
}

func checkName(name, section string) error {
	if !validName.MatchString(name) {
		return fmt.Errorf("%s.%s: names may only use a-z, 0-9, _ and -", section, name)
	}
	if name == outDirect || name == outFastest {
		return fmt.Errorf("%s.%s: %q is reserved", section, name, name)
	}
	return nil
}

// unsupportedSource explains why a pasted string can't be used.
func unsupportedSource(s string) string {
	scheme, _, _ := strings.Cut(s, "://")
	return fmt.Sprintf("%s:// links are not supported; sshproxy only connects to SSH servers", scheme)
}

// sshTarget returns the SSH destination for a proxy source; ok is false
// for other kinds of links.
func sshTarget(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if rest, ok := strings.CutPrefix(s, "ssh://"); ok {
		return strings.TrimSuffix(rest, "/"), true
	}
	return s, !strings.Contains(s, "://")
}

func (c *appConfig) proxyNames() []string {
	names := make([]string, 0, len(c.Proxies))
	for n := range c.Proxies {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

func (c *appConfig) groupNames() []string {
	names := make([]string, 0, len(c.Groups))
	for n := range c.Groups {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// outboundNames lists every name a rule or group member may use.
func (c *appConfig) outboundNames() []string {
	return append(append([]string{outDirect, outFastest}, c.proxyNames()...), c.groupNames()...)
}

// findCycle returns a group cycle like [a b a], or nil.
func (c *appConfig) findCycle() []string {
	const (
		visiting = 1
		done     = 2
	)
	state := map[string]int{}
	var path []string
	var visit func(string) []string
	visit = func(name string) []string {
		g, isGroup := c.Groups[name]
		if !isGroup || state[name] == done {
			return nil
		}
		if state[name] == visiting {
			i := slices.Index(path, name)
			return append(slices.Clone(path[i:]), name)
		}
		state[name] = visiting
		path = append(path, name)
		for _, m := range g.Members {
			if cycle := visit(m); cycle != nil {
				return cycle
			}
		}
		path = path[:len(path)-1]
		state[name] = done
		return nil
	}
	for _, name := range c.groupNames() {
		if cycle := visit(name); cycle != nil {
			return cycle
		}
	}
	return nil
}
