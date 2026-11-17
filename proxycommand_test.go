package main

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kevinburke/ssh_config"
)

// When SSHPROXY_TEST_RELAY is set, the test binary acts as a ProxyCommand:
// it relays stdin/stdout to that address, like "nc host port".
func TestMain(m *testing.M) {
	if addr := os.Getenv("SSHPROXY_TEST_RELAY"); addr != "" {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			os.Stderr.WriteString("relay: " + err.Error() + "\n")
			os.Exit(1)
		}
		go func() { io.Copy(c, os.Stdin); c.Close() }()
		io.Copy(os.Stdout, c)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestProxyCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the ProxyCommand below is sh syntax; Windows runs it with cmd")
	}
	srv := newTestServer(t)
	host, port, _ := net.SplitHostPort(srv.addr())
	exe, _ := filepath.Abs(os.Args[0])
	cfg, err := ssh_config.Decode(strings.NewReader(`
Host _*
  User tester
  Port ` + port + `
  ProxyCommand SSHPROXY_TEST_RELAY=$(echo "%h" | sed 's/^_//'):%p ` + exe + `
Host broken
  ProxyCommand /nonexistent/tool %h %p
`))
	if err != nil {
		t.Fatal(err)
	}

	d, err := resolveDest(cfg, "_"+host, "/nonexistent", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.ProxyCommand, "=$(echo \"_"+host+"\" | sed 's/^_//'):"+port+" ") {
		t.Fatalf("tokens not expanded: %q", d.ProxyCommand)
	}
	p := &scriptedPrompt{answers: []string{"secret"}}
	auth := newAuthenticator(p.prompt, filepath.Join(t.TempDir(), "known_hosts"))
	auth.useAgent = false
	c, err := newSSHManager(d, auth, t.Logf).connect()
	if err != nil {
		t.Fatal(explain(err))
	}
	c.Close()

	d, _ = resolveDest(cfg, "broken", "/nonexistent", "")
	_, err = newSSHManager(d, auth, t.Logf).connect()
	if err == nil || !strings.Contains(explain(err), "ProxyCommand: ") || !strings.Contains(explain(err), "nonexistent") {
		t.Fatalf("want the command's own error, got %v", err)
	}
}

func TestExpandTokens(t *testing.T) {
	got := expandTokens("ssh -W %h:%p %r@jump # %n %% %x", "alias", "10.0.0.1", "22", "zzn")
	if want := "ssh -W 10.0.0.1:22 zzn@jump # alias % %x"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
