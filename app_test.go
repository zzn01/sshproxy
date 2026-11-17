package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// startTestApp runs a config through startApp and serves it on a local port.
func startTestApp(t *testing.T, config string, prompt *scriptedPrompt, originURL string) (*app, string) {
	t.Helper()
	cfg, err := loadAppConfig(writeConfig(t, config))
	if err != nil {
		t.Fatal(err)
	}
	auth := newAuthenticator(prompt.prompt, filepath.Join(t.TempDir(), "known_hosts"))
	auth.useAgent = false
	hc := healthConfig{url: originURL, interval: 200 * time.Millisecond, downInterval: 100 * time.Millisecond, timeout: time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	a, err := startApp(ctx, cfg, auth, emptyConfig{}, hc, t.Logf)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); a.Close() })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go serveProxy(ln, a.router.dial, nil)
	return a, ln.Addr().String()
}

func proxyEntry(srvAddr string) string {
	return fmt.Sprintf("{ ssh: tester@%s, identity: /nonexistent }", srvAddr)
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestGroupFailoverAndRecovery(t *testing.T) {
	srvA, srvB := newTestServer(t), newTestServer(t)
	o := origin(t, false)
	config := fmt.Sprintf(`
proxies:
  a: %s
  b: %s
groups:
  main: [a, b]
rules:
  - main *
`, proxyEntry(srvA.addr()), proxyEntry(srvB.addr()))
	_, proxy := startTestApp(t, config, &scriptedPrompt{answers: []string{"secret", "secret"}}, o.URL)
	c := proxyClient("http://"+proxy, nil)
	c.Transport.(*http.Transport).DisableKeepAlives = true

	get(t, c, o.URL)
	if srvA.tunnels.Load() == 0 {
		t.Fatal("first request did not use a")
	}

	// a goes away: traffic moves to b.
	addrA, keyA := srvA.addr(), srvA.hostKey
	srvA.ln.Close()
	srvA.dropAll()
	before := srvB.tunnels.Load()
	get(t, c, o.URL+"/during")
	if srvB.tunnels.Load() == before {
		t.Fatal("request did not fail over to b")
	}

	// a comes back with the same identity: traffic returns to a.
	srvA2 := newTestServerWithKey(t, addrA, keyA)
	eventually(t, "a to come back", func() bool {
		get(t, c, o.URL+"/after")
		return srvA2.tunnels.Load() > 0
	})
}

func TestUnreachableProxyDoesNotBlockStartup(t *testing.T) {
	srv := newTestServer(t)
	o := origin(t, false)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	config := fmt.Sprintf(`
proxies:
  dead: %s
  live: %s
groups:
  main: [dead, live]
rules:
  - main *
`, proxyEntry(dead), proxyEntry(srv.addr()))
	a, proxy := startTestApp(t, config, &scriptedPrompt{answers: []string{"secret"}}, o.URL)
	if got := get(t, proxyClient("http://"+proxy, nil), o.URL+"/x"); got != "hello /x" {
		t.Fatalf("got %q", got)
	}
	if len(a.status) != 3 {
		t.Fatalf("status = %q", a.status)
	}
}

func TestLoginFailureInConfigIsFatal(t *testing.T) {
	srv := newTestServer(t)
	cfg, err := loadAppConfig(writeConfig(t, "proxies:\n  a: "+proxyEntry(srv.addr())+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	auth := newAuthenticator((&scriptedPrompt{}).prompt, filepath.Join(t.TempDir(), "known_hosts"))
	auth.useAgent = false
	if _, err := startApp(context.Background(), cfg, auth, emptyConfig{}, defaultHealth, t.Logf); err == nil {
		t.Fatal("want an error")
	}
}
