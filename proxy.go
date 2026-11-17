package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const usageHint = "This is an HTTP/HTTPS/SOCKS5 proxy, not a web server.\n" +
	"Set it as your proxy instead, e.g.: export https_proxy=http://%s\n"

// serveProxy accepts connections on ln and serves HTTP proxy and SOCKS5 on
// the same port, plus the control panel if one is given. It returns when ln
// is closed.
func serveProxy(ln net.Listener, dial dialFunc, ui *panel) error {
	httpLn := &chanListener{Listener: ln, conns: make(chan net.Conn), done: make(chan struct{})}
	srv := &http.Server{
		Handler:           &httpProxy{dial: dial, addr: ln.Addr().String(), ui: ui},
		ReadHeaderTimeout: 30 * time.Second,
	}
	go srv.Serve(httpLn)
	defer srv.Close()

	for {
		c, err := ln.Accept()
		if err != nil {
			close(httpLn.done)
			return err
		}
		go func() {
			br := bufio.NewReader(c)
			c.SetReadDeadline(time.Now().Add(30 * time.Second))
			first, err := br.Peek(1)
			c.SetReadDeadline(time.Time{})
			if err != nil {
				c.Close()
				return
			}
			bc := &bufConn{Conn: c, r: br}
			if first[0] == 5 {
				serveSOCKS5(bc, dial)
				return
			}
			select {
			case httpLn.conns <- bc:
			case <-httpLn.done:
				c.Close()
			}
		}()
	}
}

// chanListener feeds already-accepted connections to http.Server.
type chanListener struct {
	net.Listener
	conns chan net.Conn
	done  chan struct{} // closed when the real listener stops
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// bufConn is a conn whose reads go through r (which may hold peeked or
// buffered bytes).
type bufConn struct {
	net.Conn
	r io.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *bufConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// pipe copies both directions until both are done, then closes both.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	wg.Add(2)
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}

// checkHost never resolves, so a request for it only succeeds when it is
// sent through sshproxy.
const checkHost = "check.sshproxy.invalid"

type httpProxy struct {
	dial dialFunc
	addr string
	ui   *panel
	rp   *httputil.ReverseProxy
	once sync.Once
}

func (p *httpProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.connect(w, r)
		return
	}
	if r.URL.IsAbs() && r.URL.Hostname() == checkHost {
		// Answered here, so a page can tell its requests go through us.
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !r.URL.IsAbs() && p.ui != nil && p.ui.handles(r) {
		p.ui.ServeHTTP(w, r)
		return
	}
	if !r.URL.IsAbs() {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, usageHint, p.addr)
		return
	}
	p.once.Do(func() {
		p.rp = &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {},
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
					return p.dial(ctx, addr)
				},
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     90 * time.Second,
			},
			FlushInterval: -1,
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				http.Error(w, err.Error(), http.StatusBadGateway)
			},
		}
	})
	p.rp.ServeHTTP(w, r)
}

func (p *httpProxy) connect(w http.ResponseWriter, r *http.Request) {
	target, err := p.dial(r.Context(), r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		target.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	c, brw, err := hj.Hijack()
	if err != nil {
		target.Close()
		return
	}
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		c.Close()
		target.Close()
		return
	}
	pipe(&bufConn{Conn: c, r: brw.Reader}, target)
}

// SOCKS5 reply codes (RFC 1928).
const (
	socksOK              = 0x00
	socksGeneralFailure  = 0x01
	socksNotAllowed      = 0x02
	socksHostUnreachable = 0x04
	socksCmdUnsupported  = 0x07
	socksAddrUnsupported = 0x08
)

// serveSOCKS5 handles a SOCKS5 CONNECT without authentication.
func serveSOCKS5(c net.Conn, dial dialFunc) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))

	// Greeting: VER NMETHODS METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	noAuth := false
	for _, m := range methods {
		noAuth = noAuth || m == 0
	}
	if !noAuth {
		c.Write([]byte{5, 0xff})
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	var host string
	switch req[3] {
	case 1, 4:
		ip := make([]byte, map[byte]int{1: 4, 4: 16}[req[3]])
		if _, err := io.ReadFull(c, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 3:
		n := make([]byte, 1)
		if _, err := io.ReadFull(c, n); err != nil {
			return
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(c, name); err != nil {
			return
		}
		host = string(name)
	default:
		socksReply(c, socksAddrUnsupported)
		return
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(c, port); err != nil {
		return
	}
	if req[1] != 1 {
		socksReply(c, socksCmdUnsupported)
		return
	}

	addr := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port))))
	target, err := dial(context.Background(), addr)
	if err != nil {
		socksReply(c, socksErrorCode(err))
		return
	}
	if err := socksReply(c, socksOK); err != nil {
		target.Close()
		return
	}
	c.SetDeadline(time.Time{})
	pipe(c, target)
}

func socksReply(c net.Conn, code byte) error {
	_, err := c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

func socksErrorCode(err error) byte {
	var oce *ssh.OpenChannelError
	if errors.As(err, &oce) {
		if oce.Reason == ssh.Prohibited {
			return socksNotAllowed
		}
		return socksHostUnreachable
	}
	return socksGeneralFailure
}
