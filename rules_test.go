package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"testing"
)

var names = []string{"ssh", "direct", "hk"}

func TestParseRulesAndMatch(t *testing.T) {
	rs, err := parseRules(strings.NewReader(`
# comment
ssh     corp.example.com   # inline comment
DIRECT  10.1.2.3
ssh     10.0.0.0/8
hk      *.internal
direct  2001:db8::/32
`), "rules.txt", names)
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]string{
		"corp.example.com":      "ssh",
		"git.corp.example.com":  "ssh",
		"GIT.Corp.Example.com.": "ssh",
		"xcorp.example.com":     "direct",
		"example.com":           "direct",
		"10.9.9.9":              "ssh",
		"10.1.2.3":              "direct", // first match wins
		"11.0.0.1":              "direct", // unmatched goes direct
		"a.internal":            "hk",
		"2001:db8::1":           "direct",
		"google.com":            "direct",
	} {
		if got := rs.route(host); got != want {
			t.Errorf("route(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestRulesDefaultAny(t *testing.T) {
	rs, err := parseRules(strings.NewReader("direct baidu.com\nssh *\n"), "r", names)
	if err != nil {
		t.Fatal(err)
	}
	if rs.route("www.baidu.com") != "direct" || rs.route("github.com") != "ssh" {
		t.Fatal("wrong routing with catch-all rule")
	}
	// The catch-all skips this machine and the local network.
	for _, host := range []string{"192.168.1.1", "10.0.0.5", "172.16.0.1", "127.0.0.1", "::1", "fe80::1", "fd00::1", "localhost", "NAS.local."} {
		if got := rs.route(host); got != "direct" {
			t.Errorf("route(%q) = %q, want direct", host, got)
		}
	}
	if rs.route("8.8.8.8") != "ssh" || rs.route("100.64.0.1") != "ssh" {
		t.Fatal("public address skipped the catch-all")
	}
}

func TestParseRulesErrors(t *testing.T) {
	for _, in := range []string{
		"proxy example.com",
		"ssh",
		"ssh a b",
		"ssh 10.0.0.0/99",
		"ssh exa*mple.com",
	} {
		_, err := parseRules(strings.NewReader("# ok\n"+in), "r.txt", names)
		if err == nil || !strings.HasPrefix(err.Error(), "r.txt:2:") {
			t.Errorf("parseRules(%q) error = %v, want r.txt:2 error", in, err)
		}
	}
}

// fakeOutbound records the addresses it was asked to dial.
type fakeOutbound struct{ dialed []string }

func (f *fakeOutbound) Dial(_ context.Context, addr string) (net.Conn, error) {
	f.dialed = append(f.dialed, addr)
	return nil, errors.New("fake")
}

func (f *fakeOutbound) Close() error { return nil }

func TestRouterPicksNamedOutbound(t *testing.T) {
	rs, err := parseRules(strings.NewReader("hk example.com\n"), "r", names)
	if err != nil {
		t.Fatal(err)
	}
	hk, direct, ssh := &fakeOutbound{}, &fakeOutbound{}, &fakeOutbound{}
	r := &router{
		rules:     rs,
		outbounds: map[string]outbound{"hk": hk, outDirect: direct, outSSH: ssh},
		def:       outSSH,
		logf:      t.Logf,
	}
	r.dial(context.Background(), "www.example.com:443")
	r.dial(context.Background(), "other.org:80")
	if len(hk.dialed) != 1 || len(direct.dialed) != 1 || len(ssh.dialed) != 0 {
		t.Fatalf("hk=%v direct=%v ssh=%v", hk.dialed, direct.dialed, ssh.dialed)
	}

	r.rules = nil // no rules: everything to the default outbound
	r.dial(context.Background(), "other.org:80")
	if len(ssh.dialed) != 1 {
		t.Fatalf("default outbound not used: ssh=%v", ssh.dialed)
	}
	r.dial(context.Background(), "192.168.1.1:80") // except the local network
	if len(ssh.dialed) != 1 || len(direct.dialed) != 2 {
		t.Fatalf("local address not direct: ssh=%v direct=%v", ssh.dialed, direct.dialed)
	}
}

// TestRuleSetMatchesLinearScan checks the index against the reference
// first-match semantics on random rules and hosts.
func TestRuleSetMatchesLinearScan(t *testing.T) {
	rnd := rand.New(rand.NewPCG(1, 2))
	labels := []string{"a", "b", "corp", "example", "com", "cn", "net"}
	domain := func() string {
		parts := make([]string, 1+rnd.IntN(3))
		for i := range parts {
			parts[i] = labels[rnd.IntN(len(labels))]
		}
		return strings.Join(parts, ".")
	}
	ip := func() string {
		if rnd.IntN(4) == 0 {
			return fmt.Sprintf("2001:db8::%x", rnd.IntN(16))
		}
		return fmt.Sprintf("10.%d.%d.%d", rnd.IntN(3), rnd.IntN(3), rnd.IntN(3))
	}
	for range 200 {
		var lines []string
		for range 1 + rnd.IntN(20) {
			out := names[rnd.IntN(len(names))]
			var pat string
			switch rnd.IntN(5) {
			case 0, 1:
				pat = domain()
			case 2:
				pat = ip()
			case 3:
				pat = fmt.Sprintf("%s/%d", ip(), []int{8, 16, 24, 32}[rnd.IntN(4)])
				if strings.Contains(pat, ":") {
					pat = fmt.Sprintf("2001:db8::/%d", []int{32, 64, 120}[rnd.IntN(3)])
				}
			case 4:
				pat = "*"
			}
			lines = append(lines, out+" "+pat)
		}
		rs, err := parseRules(strings.NewReader(strings.Join(lines, "\n")), "r", names)
		if err != nil {
			t.Fatal(err)
		}
		for range 50 {
			host := domain()
			if rnd.IntN(2) == 0 {
				host = ip()
			}
			want := outDirect
			for _, r := range rs.rules {
				if r.match(host) {
					want = r.out
					break
				}
			}
			if got := rs.route(host); got != want {
				t.Fatalf("route(%q) = %q, want %q\nrules:\n%s", host, got, want, strings.Join(lines, "\n"))
			}
		}
	}
}

func BenchmarkRuleSet100k(b *testing.B) {
	var sb strings.Builder
	for i := range 100000 {
		fmt.Fprintf(&sb, "ssh site%d.example.com\n", i)
	}
	rs, err := parseRules(strings.NewReader(sb.String()), "r", names)
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		rs.route("www.notmatched.org")
	}
}
