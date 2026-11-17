package main

import (
	"strings"
	"testing"

	"github.com/kevinburke/ssh_config"
)

func TestParseTarget(t *testing.T) {
	for in, want := range map[string][3]string{
		"host":          {"", "host", ""},
		"bob@host":      {"bob", "host", ""},
		"bob@host:2222": {"bob", "host", "2222"},
		"a@b@host":      {"a@b", "host", ""},
		"[::1]:22":      {"", "::1", "22"},
		"[::1]":         {"", "::1", ""},
		"root@fe80::1":  {"root", "fe80::1", ""},
		"1.2.3.4:22":    {"", "1.2.3.4", "22"},
	} {
		u, h, p, err := parseTarget(in)
		if err != nil || [3]string{u, h, p} != want {
			t.Errorf("parseTarget(%q) = %q %q %q %v, want %q", in, u, h, p, err, want)
		}
	}
	for _, in := range []string{"", "bob@"} {
		if _, _, _, err := parseTarget(in); err == nil {
			t.Errorf("parseTarget(%q) want error", in)
		}
	}
}

func TestResolveDest(t *testing.T) {
	cfg, err := ssh_config.Decode(strings.NewReader(`
Host web
  HostName 10.0.0.5
  User deploy
  Port 2200
  IdentityFile /keys/web
  ProxyJump bastion

Host bastion
  HostName bastion.example.com
  User jumper
`))
	if err != nil {
		t.Fatal(err)
	}

	d, err := resolveDest(cfg, "web", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if d.String() != "deploy@10.0.0.5:2200" || d.IdentityFiles[0] != "/keys/web" {
		t.Fatalf("got %s %v", d, d.IdentityFiles)
	}
	if d.Jump == nil || d.Jump.String() != "jumper@bastion.example.com:22" {
		t.Fatalf("jump = %v", d.Jump)
	}

	// CLI values win over the config file.
	d, err = resolveDest(cfg, "root@web:22", "/my/key", "none")
	if err != nil {
		t.Fatal(err)
	}
	if d.String() != "root@10.0.0.5:22" || d.IdentityFiles[0] != "/my/key" || d.Jump != nil {
		t.Fatalf("got %s %v %v", d, d.IdentityFiles, d.Jump)
	}

	if _, err := resolveDest(cfg, "web", "", "a,b"); err == nil {
		t.Fatal("multi-hop jump should be rejected")
	}

	d, err = resolveDest(emptyConfig{}, "1.2.3.4", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Port != "22" || d.User == "" {
		t.Fatalf("defaults not applied: %s", d)
	}
}
