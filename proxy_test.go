package main

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// testServer is an in-process SSH server with password auth that serves
// direct-tcpip by dialing locally.
type testServer struct {
	ln        net.Listener
	password  string
	forbid    atomic.Bool  // reject direct-tcpip as prohibited
	tunnels   atomic.Int32 // direct-tcpip channels opened
	mu        sync.Mutex
	conns     []net.Conn
	byTarget  map[string]int // tunnels per target address
	hostKey   ssh.Signer
	authFails atomic.Int32
}

func newTestServer(t *testing.T) *testServer {
	return newTestServerOn(t, "127.0.0.1:0")
}

func newTestServerOn(t *testing.T, addr string) *testServer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(nil)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return newTestServerWithKey(t, addr, signer)
}

func newTestServerWithKey(t *testing.T, addr string, signer ssh.Signer) *testServer {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	s := &testServer{ln: ln, password: "secret", hostKey: signer}
	t.Cleanup(func() { ln.Close(); s.dropAll() })
	go s.serve()
	return s
}

func (s *testServer) addr() string { return s.ln.Addr().String() }

// tunnelsTo counts tunnels opened to the server behind url.
func (s *testServer) tunnelsTo(rawURL string) int {
	u, _ := url.Parse(rawURL)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byTarget[u.Host]
}

func (s *testServer) dest() *dest {
	host, port, _ := net.SplitHostPort(s.addr())
	return &dest{User: "tester", Host: host, Port: port, IdentityFiles: []string{"/nonexistent"}}
}

func (s *testServer) dropAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		c.Close()
	}
	s.conns = nil
}

func (s *testServer) setHostKey(k ssh.Signer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostKey = k
}

func (s *testServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns = append(s.conns, c)
		key := s.hostKey
		s.mu.Unlock()
		go s.handle(c, s.config(key))
	}
}

func (s *testServer) config(key ssh.Signer) *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if string(pw) == s.password {
				return nil, nil
			}
			s.authFails.Add(1)
			return nil, errors.New("bad password")
		},
	}
	cfg.AddHostKey(key)
	return cfg
}

func (s *testServer) handle(c net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		c.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "direct-tcpip" {
			nc.Reject(ssh.UnknownChannelType, "")
			continue
		}
		if s.forbid.Load() {
			nc.Reject(ssh.Prohibited, "forwarding disabled")
			continue
		}
		var msg struct {
			Host  string
			Port  uint32
			OHost string
			OPort uint32
		}
		ssh.Unmarshal(nc.ExtraData(), &msg)
		if strings.HasSuffix(msg.Host, ".test") {
			msg.Host = "127.0.0.1" // remote names for origins on this machine
		}
		target, err := net.Dial("tcp", net.JoinHostPort(msg.Host, strconv.Itoa(int(msg.Port))))
		if err != nil {
			nc.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			target.Close()
			continue
		}
		s.tunnels.Add(1)
		s.mu.Lock()
		if s.byTarget == nil {
			s.byTarget = map[string]int{}
		}
		s.byTarget[target.RemoteAddr().String()]++
		s.mu.Unlock()
		go ssh.DiscardRequests(creqs)
		go func() {
			go func() { io.Copy(ch, target); ch.CloseWrite() }()
			io.Copy(target, ch)
			target.Close()
			ch.Close()
		}()
	}
}

// scriptedPrompt answers prompts from a list and counts calls.
type scriptedPrompt struct {
	mu      sync.Mutex
	answers []string
	calls   int
}

func (p *scriptedPrompt) prompt(string, bool) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if len(p.answers) == 0 {
		return "", errNoTerminal
	}
	a := p.answers[0]
	p.answers = p.answers[1:]
	return a, nil
}

func (p *scriptedPrompt) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

type harness struct {
	srv    *testServer
	prompt *scriptedPrompt
	m      *sshManager
	proxy  string // host:port of the local proxy
}

func setup(t *testing.T, rs *ruleSet) *harness {
	t.Helper()
	srv := newTestServer(t)
	p := &scriptedPrompt{answers: []string{"secret"}}
	auth := newAuthenticator(p.prompt, filepath.Join(t.TempDir(), "known_hosts"))
	auth.useAgent = false
	m := newSSHManager(srv.dest(), auth, t.Logf)
	c, err := m.connect()
	if err != nil {
		t.Fatal(explain(err))
	}
	t.Cleanup(func() { m.Close() })
	go m.run(c)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	r := &router{
		rules:     rs,
		outbounds: map[string]outbound{outSSH: m, outDirect: &directOutbound{}},
		def:       outSSH,
		logf:      t.Logf,
	}
	go serveProxy(ln, r.dial, nil)
	return &harness{srv: srv, prompt: p, m: m, proxy: ln.Addr().String()}
}

func proxyClient(proxy string, tlsCfg *http.Transport) *http.Client {
	u, _ := url.Parse(proxy)
	tr := &http.Transport{Proxy: http.ProxyURL(u)}
	if tlsCfg != nil {
		tr.TLSClientConfig = tlsCfg.TLSClientConfig
	}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func get(t *testing.T, c *http.Client, u string) string {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: %s: %s", u, resp.Status, b)
	}
	return string(b)
}

func origin(t *testing.T, tls bool) *httptest.Server {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "hello "+r.URL.Path) })
	var s *httptest.Server
	if tls {
		s = httptest.NewTLSServer(h)
	} else {
		s = httptest.NewServer(h)
	}
	t.Cleanup(s.Close)
	// A name only the test SSH server resolves: sshproxy sends local
	// addresses like 127.0.0.1 direct, not through SSH.
	s.URL = strings.Replace(s.URL, "127.0.0.1", "origin.test", 1)
	return s
}

func TestHTTP(t *testing.T) {
	h := setup(t, nil)
	o := origin(t, false)
	if got := get(t, proxyClient("http://"+h.proxy, nil), o.URL+"/a"); got != "hello /a" {
		t.Fatalf("got %q", got)
	}
	if h.srv.tunnels.Load() == 0 {
		t.Fatal("request did not go through SSH")
	}
}

func TestHTTPSConnect(t *testing.T) {
	h := setup(t, nil)
	o := origin(t, true)
	tr := o.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.ServerName = "example.com" // in the test certificate
	c := proxyClient("http://"+h.proxy, tr)
	if got := get(t, c, o.URL+"/b"); got != "hello /b" {
		t.Fatalf("got %q", got)
	}
}

func TestSOCKS5(t *testing.T) {
	h := setup(t, nil)
	o := origin(t, false)
	if got := get(t, proxyClient("socks5://"+h.proxy, nil), o.URL+"/c"); got != "hello /c" {
		t.Fatalf("got %q", got)
	}
	if h.srv.tunnels.Load() == 0 {
		t.Fatal("request did not go through SSH")
	}
}

func TestSOCKS5Prohibited(t *testing.T) {
	h := setup(t, nil)
	h.srv.forbid.Store(true)
	c, err := net.Dial("tcp", h.proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte{5, 1, 0})
	reply := make([]byte, 2)
	io.ReadFull(c, reply)
	req := []byte{5, 1, 0, 1, 192, 0, 2, 1, 0, 0}
	binary.BigEndian.PutUint16(req[8:], 80)
	c.Write(req)
	resp := make([]byte, 10)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatal(err)
	}
	if resp[1] != socksNotAllowed {
		t.Fatalf("reply code = %d, want %d", resp[1], socksNotAllowed)
	}
}

func TestHTTPProhibitedMessage(t *testing.T) {
	h := setup(t, nil)
	h.srv.forbid.Store(true)
	o := origin(t, false)
	resp, err := proxyClient("http://"+h.proxy, nil).Get(o.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(string(b), "AllowTcpForwarding") {
		t.Fatalf("got %s: %s", resp.Status, b)
	}
}

func TestNotAProxyRequest(t *testing.T) {
	h := setup(t, nil)
	resp, err := http.Get("http://" + h.proxy + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got %s", resp.Status)
	}
}

func TestReconnectWithoutPrompt(t *testing.T) {
	h := setup(t, nil)
	o := origin(t, false)
	c := proxyClient("http://"+h.proxy, nil)
	get(t, c, o.URL)

	h.srv.dropAll()
	c.CloseIdleConnections()
	if got := get(t, c, o.URL+"/again"); got != "hello /again" {
		t.Fatalf("got %q", got)
	}
	if n := h.prompt.count(); n != 1 {
		t.Fatalf("prompted %d times, want 1", n)
	}
}

func TestWrongPasswordReprompts(t *testing.T) {
	srv := newTestServer(t)
	p := &scriptedPrompt{answers: []string{"wrong", "secret"}}
	auth := newAuthenticator(p.prompt, filepath.Join(t.TempDir(), "known_hosts"))
	auth.useAgent = false
	c, err := newSSHManager(srv.dest(), auth, t.Logf).connect()
	if err != nil {
		t.Fatal(explain(err))
	}
	c.Close()
	if p.count() != 2 {
		t.Fatalf("prompted %d times, want 2", p.count())
	}
}

func TestAuthFailureMessage(t *testing.T) {
	srv := newTestServer(t)
	p := &scriptedPrompt{answers: []string{"a", "b", "c"}}
	auth := newAuthenticator(p.prompt, filepath.Join(t.TempDir(), "known_hosts"))
	auth.useAgent = false
	_, err := newSSHManager(srv.dest(), auth, t.Logf).connect()
	if err == nil || !strings.Contains(explain(err), "login rejected") {
		t.Fatalf("got %v", err)
	}
}

func TestHostKeyTOFUAndMismatch(t *testing.T) {
	kh := filepath.Join(t.TempDir(), "sub", "known_hosts")
	srv := newTestServer(t)
	connect := func() error {
		p := &scriptedPrompt{answers: []string{"secret"}}
		auth := newAuthenticator(p.prompt, kh)
		auth.useAgent = false
		c, err := newSSHManager(srv.dest(), auth, t.Logf).connect()
		if err == nil {
			c.Close()
		}
		return err
	}
	if err := connect(); err != nil {
		t.Fatal(explain(err))
	}
	if b, _ := os.ReadFile(kh); len(b) == 0 {
		t.Fatal("known_hosts not written")
	}
	if err := connect(); err != nil {
		t.Fatalf("second connect: %v", explain(err))
	}

	_, priv, _ := ed25519.GenerateKey(nil)
	newKey, _ := ssh.NewSignerFromKey(priv)
	srv.setHostKey(newKey)
	err := connect()
	var hk *hostKeyChangedError
	if !errors.As(err, &hk) {
		t.Fatalf("got %v, want host key changed", err)
	}
}

func TestDirectRouteBypassesSSH(t *testing.T) {
	rs := newRuleSet([]rule{{out: outSSH, domain: "example.invalid"}})
	h := setup(t, rs)
	o := origin(t, false)
	get(t, proxyClient("http://"+h.proxy, nil), strings.Replace(o.URL, "origin.test", "127.0.0.1", 1))
	if n := h.srv.tunnels.Load(); n != 0 {
		t.Fatalf("direct request opened %d SSH tunnels", n)
	}
}

func TestStartupRetriesUntilServerIsUp(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	host, port, _ := net.SplitHostPort(addr)
	d := &dest{User: "tester", Host: host, Port: port, IdentityFiles: []string{"/nonexistent"}}

	p := &scriptedPrompt{answers: []string{"secret"}}
	auth := newAuthenticator(p.prompt, filepath.Join(t.TempDir(), "known_hosts"))
	auth.useAgent = false
	time.AfterFunc(500*time.Millisecond, func() { newTestServerOn(t, addr) })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := newSSHManager(d, auth, t.Logf).connectWithRetry(ctx)
	if err != nil {
		t.Fatal(explain(err))
	}
	c.Close()
}

func TestStartupDoesNotRetryAuthFailure(t *testing.T) {
	srv := newTestServer(t)
	p := &scriptedPrompt{}
	auth := newAuthenticator(p.prompt, filepath.Join(t.TempDir(), "known_hosts"))
	auth.useAgent = false
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := newSSHManager(srv.dest(), auth, t.Logf).connectWithRetry(ctx)
	if err == nil || ctx.Err() != nil {
		t.Fatalf("got %v, want an immediate error", err)
	}
}
