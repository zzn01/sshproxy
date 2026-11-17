package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/kevinburke/ssh_config"
)

// dest is a fully resolved SSH destination.
type dest struct {
	User          string
	Host          string // real hostname or IP to connect to
	Port          string
	IdentityFiles []string
	Jump          *dest
	ProxyCommand  string // command whose stdin/stdout is the connection
}

func (d *dest) addr() string { return net.JoinHostPort(d.Host, d.Port) }

func (d *dest) String() string { return d.User + "@" + d.addr() }

// label is user@host for prompts, with the port only when it isn't 22.
func (d *dest) label() string {
	if d.Port == "22" {
		return d.User + "@" + d.Host
	}
	return d.String()
}

// sshConfig is the subset of ~/.ssh/config lookups we need.
type sshConfig interface {
	Get(alias, key string) (string, error)
	GetAll(alias, key string) ([]string, error)
}

// emptyConfig is used when there is no ~/.ssh/config.
type emptyConfig struct{}

func (emptyConfig) Get(string, string) (string, error)      { return "", nil }
func (emptyConfig) GetAll(string, string) ([]string, error) { return nil, nil }

// loadSSHConfig reads ~/.ssh/config. A missing or unparsable file is not
// fatal: users without SSH experience usually have none.
func loadSSHConfig() sshConfig {
	home, err := os.UserHomeDir()
	if err != nil {
		return emptyConfig{}
	}
	f, err := os.Open(filepath.Join(home, ".ssh", "config"))
	if err != nil {
		return emptyConfig{}
	}
	defer f.Close()
	cfg, err := ssh_config.Decode(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: ignoring ~/.ssh/config: %v\n", err)
		return emptyConfig{}
	}
	return cfg
}

// parseTarget splits "[user@]host[:port]". Bare IPv6 addresses without
// brackets are accepted as a host without port.
func parseTarget(s string) (usr, host, port string, err error) {
	if i := strings.LastIndex(s, "@"); i >= 0 {
		usr, s = s[:i], s[i+1:]
	}
	host = s
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		host = s[1 : len(s)-1]
	} else if strings.Count(s, ":") == 1 || strings.HasPrefix(s, "[") {
		if host, port, err = net.SplitHostPort(s); err != nil {
			return "", "", "", fmt.Errorf("invalid destination %q", s)
		}
	}
	if host == "" {
		return "", "", "", errors.New("destination host is empty")
	}
	return usr, host, port, nil
}

// resolveDest combines the CLI target with ~/.ssh/config. Explicit CLI
// values win over the config file, which wins over defaults.
func resolveDest(cfg sshConfig, target, identity, jump string) (*dest, error) {
	d, err := resolveHost(cfg, target)
	if err != nil {
		return nil, err
	}
	if identity != "" {
		d.IdentityFiles = []string{expandHome(identity)}
	}
	if jump == "" {
		jump, _ = cfg.Get(alias(target), "ProxyJump")
	}
	if jump != "" && !strings.EqualFold(jump, "none") {
		if strings.Contains(jump, ",") {
			return nil, fmt.Errorf("multi-hop jump %q is not supported, use a single jump host", jump)
		}
		if d.Jump, err = resolveHost(cfg, jump); err != nil {
			return nil, fmt.Errorf("jump host: %w", err)
		}
	}
	return d, nil
}

func alias(target string) string {
	_, host, _, _ := parseTarget(target)
	return host
}

func resolveHost(cfg sshConfig, target string) (*dest, error) {
	usr, host, port, err := parseTarget(target)
	if err != nil {
		return nil, err
	}
	get := func(key string) string {
		v, _ := cfg.Get(host, key)
		return v
	}
	d := &dest{User: usr, Host: host, Port: port}
	if h := get("HostName"); h != "" {
		d.Host = expandTokens(h, host, host, "", "")
	}
	if d.User == "" {
		d.User = get("User")
	}
	if d.User == "" {
		d.User = currentUser()
	}
	if d.Port == "" {
		d.Port = get("Port")
	}
	if d.Port == "" {
		d.Port = "22"
	}
	files, _ := cfg.GetAll(host, "IdentityFile")
	for _, f := range files {
		d.IdentityFiles = append(d.IdentityFiles, expandHome(f))
	}
	if pc := get("ProxyCommand"); pc != "" && !strings.EqualFold(pc, "none") {
		d.ProxyCommand = expandTokens(pc, host, d.Host, d.Port, d.User)
	}
	return d, nil
}

// expandTokens replaces the ssh_config tokens %h (host name), %n (name as
// typed), %p (port), %r (user) and %%.
func expandTokens(s, alias, host, port, user string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'h':
			b.WriteString(host)
		case 'n':
			b.WriteString(alias)
		case 'p':
			b.WriteString(port)
		case 'r':
			b.WriteString(user)
		case '%':
			b.WriteByte('%')
		default:
			b.WriteByte('%')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func currentUser() string {
	u, err := user.Current()
	if err != nil {
		return "root"
	}
	// Windows returns DOMAIN\name.
	if _, name, ok := strings.Cut(u.Username, `\`); ok {
		return name
	}
	return u.Username
}

func expandHome(p string) string {
	if rest, ok := strings.CutPrefix(p, "~"); ok {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, rest)
		}
	}
	return p
}
