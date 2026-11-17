package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	dialTimeout       = 10 * time.Second
	keepaliveInterval = 15 * time.Second
	keepaliveTimeout  = 10 * time.Second
	waitForConnection = 15 * time.Second
	maxBackoff        = 30 * time.Second
)

// sshManager keeps one SSH connection alive and opens tunnels through it.
type sshManager struct {
	dest *dest
	auth *authenticator
	logf func(format string, args ...any)

	ctx    context.Context // canceled by Close
	cancel context.CancelFunc
	failed atomic.Bool // gave up reconnecting

	mu     sync.Mutex
	client *ssh.Client
	ready  chan struct{} // closed once client is set
}

func newSSHManager(d *dest, auth *authenticator, logf func(string, ...any)) *sshManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &sshManager{dest: d, auth: auth, logf: logf, ctx: ctx, cancel: cancel, ready: make(chan struct{})}
}

// Close stops reconnecting and closes the current connection.
func (m *sshManager) Close() error {
	m.cancel()
	return nil
}

// unreachableError means the TCP connection to the SSH server failed.
type unreachableError struct {
	addr string
	err  error
}

func (e *unreachableError) Error() string { return fmt.Sprintf("can't reach %s: %v", e.addr, e.err) }
func (e *unreachableError) Unwrap() error { return e.err }

// connect establishes a new SSH client, through the jump host if any.
func (m *sshManager) connect() (*ssh.Client, error) {
	var jump *ssh.Client
	if m.dest.Jump != nil {
		var err error
		if jump, err = m.handshake(nil, m.dest.Jump); err != nil {
			return nil, err
		}
	}
	c, err := m.handshake(jump, m.dest)
	if err != nil {
		if jump != nil {
			jump.Close()
		}
		return nil, err
	}
	if jump != nil {
		go func() {
			c.Wait()
			jump.Close()
		}()
	}
	return c, nil
}

func (m *sshManager) handshake(via *ssh.Client, d *dest) (*ssh.Client, error) {
	var conn net.Conn
	var err error
	switch {
	case via != nil:
		conn, err = via.Dial("tcp", d.addr())
	case d.ProxyCommand != "":
		conn, err = dialCommand(d.ProxyCommand)
	default:
		conn, err = net.DialTimeout("tcp", d.addr(), dialTimeout)
	}
	if err != nil {
		return nil, &unreachableError{addr: d.addr(), err: err}
	}
	cfg, cleanup := m.auth.clientConfig(d)
	defer cleanup()
	sc, chans, reqs, err := ssh.NewClientConn(conn, d.addr(), cfg)
	if err != nil {
		conn.Close()
		if cc, ok := conn.(*commandConn); ok && cc.stderr() != "" {
			// The command failed (e.g. "nc: command not found").
			return nil, &unreachableError{addr: d.addr(), err: fmt.Errorf("ProxyCommand: %s", cc.stderr())}
		}
		return nil, fmt.Errorf("%s: %w", d, err)
	}
	return ssh.NewClient(sc, chans, reqs), nil
}

// run serves on c and reconnects whenever the connection drops, until
// Close is called or a reconnect fails in a way retrying can't fix. A nil c
// means "connect first" (the server was unreachable at startup).
func (m *sshManager) run(c *ssh.Client) {
	ctx := m.ctx
	for {
		if c == nil {
			if c = m.reconnect(ctx); c == nil {
				return
			}
			m.logf("Connected to %s", m.dest.Host)
		}
		m.setClient(c)
		stop := context.AfterFunc(ctx, func() { c.Close() })
		done := make(chan struct{})
		go keepalive(c, done)
		c.Wait()
		close(done)
		stop()
		m.clearClient()
		if ctx.Err() != nil {
			return
		}
		m.logf("Disconnected from %s, reconnecting...", m.dest.Host)
		c = nil
	}
}

// reconnect retries until connected. Errors that retrying can't fix (login
// rejected after re-prompting, changed host key) disable this connection.
func (m *sshManager) reconnect(ctx context.Context) *ssh.Client {
	backoff := time.Second
	for {
		c, err := m.connect()
		if err == nil {
			return c
		}
		if isFatal(err) {
			m.logf("%s\nGiving up on %s; fix the problem and restart sshproxy.", explain(err), m.dest.Host)
			m.failed.Store(true)
			return nil
		}
		m.logf("Reconnect failed: %s (retrying in %s)", explain(err), backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

// connectWithRetry makes the first connection. An unreachable server (e.g.
// the network is not up yet) is retried; any other error is returned,
// since retrying cannot fix a wrong password or a changed host key.
func (m *sshManager) connectWithRetry(ctx context.Context) (*ssh.Client, error) {
	backoff := time.Second
	for {
		c, err := m.connect()
		if !errors.As(err, new(*unreachableError)) {
			return c, err
		}
		m.logf("%s (retrying in %s, Ctrl+C to quit)", explain(err), backoff)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

// isFatal reports connect errors that retrying cannot fix.
func isFatal(err error) bool {
	var hk *hostKeyChangedError
	return errors.As(err, &hk) || errors.Is(err, errNoTerminal) || errors.Is(err, errPromptCanceled) ||
		strings.Contains(err.Error(), "unable to authenticate")
}

// connected reports whether the SSH connection is up.
func (m *sshManager) connected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.client != nil
}

func (m *sshManager) setClient(c *ssh.Client) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.client = c
	close(m.ready)
}

func (m *sshManager) clearClient() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.client = nil
	m.ready = make(chan struct{})
}

// keepalive closes c when the server stops answering.
func keepalive(c *ssh.Client, done <-chan struct{}) {
	t := time.NewTicker(keepaliveInterval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
		}
		res := make(chan error, 1)
		go func() {
			_, _, err := c.SendRequest("keepalive@openssh.com", true, nil)
			res <- err
		}()
		select {
		case err := <-res:
			if err != nil {
				c.Close()
				return
			}
		case <-time.After(keepaliveTimeout):
			c.Close()
			return
		case <-done:
			return
		}
	}
}

// Dial opens a tunnel to addr. The hostname is resolved by the SSH server.
// While reconnecting it waits briefly for the connection to come back.
func (m *sshManager) Dial(ctx context.Context, addr string) (net.Conn, error) {
	if m.failed.Load() {
		return nil, fmt.Errorf("SSH connection to %s is disabled after a login or host key error", m.dest.Host)
	}
	ctx, cancel := context.WithTimeout(ctx, waitForConnection)
	defer cancel()
	for {
		m.mu.Lock()
		c, ready := m.client, m.ready
		m.mu.Unlock()
		if c != nil {
			return c.DialContext(ctx, "tcp", addr)
		}
		select {
		case <-ready:
		case <-ctx.Done():
			return nil, errors.New("SSH connection is down, reconnecting")
		}
	}
}

// explain turns errors into plain-language messages.
func explain(err error) string {
	var hk *hostKeyChangedError
	var ue *unreachableError
	var oce *ssh.OpenChannelError
	switch {
	case errors.As(err, &hk):
		return hk.Error()
	case errors.Is(err, errNoTerminal):
		return errNoTerminal.Error()
	case errors.As(err, &ue):
		return ue.Error() + " (check the address, port and your network)"
	case strings.Contains(err.Error(), "unable to authenticate"):
		return "login rejected: wrong password, or the server does not accept your key"
	case errors.As(err, &oce) && oce.Reason == ssh.Prohibited:
		return "the SSH server refused to forward the connection (administratively prohibited); " +
			"TCP forwarding is probably disabled on the server (AllowTcpForwarding no)"
	}
	return err.Error()
}
