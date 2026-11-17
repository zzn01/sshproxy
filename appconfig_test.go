package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExampleConfigIsValid(t *testing.T) {
	cfg, err := loadAppConfig(writeConfig(t, exampleConfig))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Proxies["office"].Jump != "bastion" || cfg.Groups["main"].Type != policyFallback {
		t.Fatalf("parsed %+v", cfg)
	}
	if got := cfg.rules.route("git.corp.example.com"); got != "office" {
		t.Fatalf("route = %q", got)
	}
}

func TestConfigSingleProxyNeedsNoRules(t *testing.T) {
	cfg, err := loadAppConfig(writeConfig(t, "proxies:\n  hk: ssh://root@1.2.3.4:22\n"))
	if err != nil {
		t.Fatal(err)
	}
	if target, _ := sshTarget(cfg.Proxies["hk"].SSH); target != "root@1.2.3.4:22" {
		t.Fatalf("target = %q", target)
	}
}

func TestConfigFastestGroup(t *testing.T) {
	cfg, err := loadAppConfig(writeConfig(t, `
proxies: { a: h1, b: h2 }
groups:
  auto: { type: fastest, members: [a, b] }
rules: ["auto *"]
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Groups["auto"].Type != policyFastest {
		t.Fatalf("type = %q", cfg.Groups["auto"].Type)
	}
}

func TestConfigErrors(t *testing.T) {
	for _, tc := range []struct{ config, want string }{
		{"proxys: {}", `field proxys not found`},
		{"proxies: {}", "no proxies"},
		{"proxies:\n  hk: { ssh: h, user: x }", `line 2: unknown key "user"`},
		{"proxies:\n  HK: h", "names may only use"},
		{"proxies:\n  direct: h", "reserved"},
		{"proxies:\n  hk: 'vless://u@h:443'", "line 2: proxies.hk: vless:// links are not supported"},
		{"proxies: { a: h1 }\ngroups:\n  g: [a, nope]", `unknown member "nope"`},
		{"proxies: { a: h1 }\ngroups:\n  g: { type: random, members: [a] }", `unknown type "random"`},
		{"proxies: { a: h1 }\ngroups:\n  a: [a]", "a proxy has the same name"},
		{"proxies: { a: h1 }\ngroups:\n  x: [y]\n  y: [x]", "x -> y -> x"},
		{"proxies: { a: h1 }\nrules:\n  - a *\n  - b *", `line 4: unknown outbound "b"`},
	} {
		_, err := loadAppConfig(writeConfig(t, tc.config))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("config %q: error %v, want %q", tc.config, err, tc.want)
		}
	}
}
