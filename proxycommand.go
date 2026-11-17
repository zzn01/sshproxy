package main

import (
	"bytes"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// dialCommand runs an ssh_config ProxyCommand and uses its stdin and stdout
// as the connection, like OpenSSH does.
func dialCommand(command string) (net.Conn, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", command)
	} else {
		cmd = exec.Command("/bin/sh", "-c", command)
		// Apps started from the Finder get a minimal PATH; add the usual
		// places for tools like nc or cloudflared.
		cmd.Env = append(os.Environ(), "PATH="+os.Getenv("PATH")+":/usr/local/bin:/opt/homebrew/bin")
	}
	c := &commandConn{cmd: cmd}
	cmd.Stderr = &c.errBuf
	var err error
	if c.w, err = cmd.StdinPipe(); err != nil {
		return nil, err
	}
	if c.r, err = cmd.StdoutPipe(); err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return c, nil
}

// commandConn is a net.Conn over a child process's stdout / stdin.
type commandConn struct {
	cmd  *exec.Cmd
	r    io.ReadCloser
	w    io.WriteCloser
	once sync.Once

	errBuf lockedBuffer
}

func (c *commandConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *commandConn) Write(p []byte) (int, error) { return c.w.Write(p) }

func (c *commandConn) Close() error {
	c.once.Do(func() {
		c.w.Close()
		c.cmd.Process.Kill()
		go c.cmd.Wait()
	})
	return nil
}

// stderr is what the command printed, for error messages.
func (c *commandConn) stderr() string {
	time.Sleep(50 * time.Millisecond) // let a failing command finish writing
	return strings.TrimSpace(c.errBuf.String())
}

// Addresses are unknown; an empty TCP address still parses as host:port,
// which host key checking needs.
func (c *commandConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *commandConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *commandConn) SetDeadline(time.Time) error      { return nil }
func (c *commandConn) SetReadDeadline(time.Time) error  { return nil }
func (c *commandConn) SetWriteDeadline(time.Time) error { return nil }

// lockedBuffer is a bytes.Buffer safe for the process writer and readers.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.b.Len() > 4096 {
		return len(p), nil
	}
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
