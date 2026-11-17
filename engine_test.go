package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kevinburke/ssh_config"
)

func TestSuggestName(t *testing.T) {
	for src, want := range map[string]string{
		"root@10.0.0.5:2222":    "10-0-0-5",
		"ssh://gcp-hk-01":       "gcp-hk-01",
		"me@Office.Example.com": "office-example-com",
		"direct":                "proxy",
	} {
		if got := suggestName(src); got != want {
			t.Errorf("suggestName(%q) = %q, want %q", src, got, want)
		}
	}
}

func TestConfigSaveRoundTrip(t *testing.T) {
	cfg, err := loadAppConfig(writeConfig(t, exampleConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.path = filepath.Join(t.TempDir(), "sub", "config.yaml")
	cfg.Groups["auto"] = groupSpec{Type: policyFastest, Members: []string{"hk", "office"}}
	if err := cfg.save(); err != nil {
		t.Fatal(err)
	}
	again, err := loadAppConfig(cfg.path)
	if err != nil {
		data, _ := os.ReadFile(cfg.path)
		t.Fatalf("%v\n%s", err, data)
	}
	if again.Proxies["office"].Jump != "bastion" || again.Proxies["hk"].SSH != "root@1.2.3.4" ||
		again.Groups["auto"].Type != policyFastest || !slices.Equal(again.Groups["main"].Members, []string{"hk", "office"}) ||
		len(again.Rules) != 3 {
		t.Fatalf("round trip lost data: %+v", again)
	}
}

func testHealth(probeURL string) healthConfig {
	return healthConfig{url: probeURL, interval: 200 * time.Millisecond, downInterval: 100 * time.Millisecond, timeout: time.Second}
}

// addServer starts a test SSH server and adds it through the panel's form.
func addServer(t *testing.T, e *engine, name string) *testServer {
	t.Helper()
	srv := newTestServer(t)
	host, port, _ := net.SplitHostPort(srv.addr())
	form := sshForm{Host: host, Port: port, User: "tester", Password: "secret", Identity: "/nonexistent", Name: name}
	if _, err := e.addSSH(form); err != nil {
		t.Fatal(err)
	}
	return srv
}

// testEngine runs an engine on an empty config in a temp dir.
func testEngine(t *testing.T, prompt promptFunc, probeURL string) (*engine, string) {
	t.Helper()
	auth := newAuthenticator(prompt, filepath.Join(t.TempDir(), "known_hosts"))
	auth.useAgent = false
	e := newEngine(filepath.Join(t.TempDir(), "config.yaml"), auth, emptyConfig{}, testHealth(probeURL), &logBuffer{})
	t.Cleanup(e.close)
	if err := e.reload(); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go serveProxy(ln, e.dial, nil)
	return e, ln.Addr().String()
}

func TestEngineAddAndRemoveSources(t *testing.T) {
	o := origin(t, false)
	probe := origin(t, false)
	e, proxy := testEngine(t, (&scriptedPrompt{}).prompt, probe.URL)

	// Empty config: requests fail with a hint instead of hanging.
	resp, err := proxyClient("http://"+proxy, nil).Get(o.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("empty config: %s", resp.Status)
	}

	srvA := addServer(t, e, "a")
	host, port, _ := net.SplitHostPort(srvA.addr())
	dup := sshForm{Host: host, Port: port, User: "tester", Password: "secret", Identity: "/nonexistent", Name: "again"}
	if _, err := e.addSSH(dup); err == nil || !strings.Contains(err.Error(), "already added") {
		t.Fatalf("duplicate: %v", err)
	}
	srvB := addServer(t, e, "b")
	if got := get(t, proxyClient("http://"+proxy, nil), o.URL+"/two"); got != "hello /two" {
		t.Fatalf("got %q", got)
	}
	// Two sources and no rules: an implicit fastest group takes everything.
	if g := e.app.groups; len(g) != 1 || g[0].name != outFastest {
		t.Fatalf("groups %+v", g)
	}

	if err := e.setRouting(nil, "a"); err != nil {
		t.Fatal(err)
	}
	if err := e.removeSource("a"); err != nil {
		t.Fatal(err)
	}
	saved, err := loadAppConfig(e.path)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Proxies) != 1 || saved.Proxies["b"].SSH != "tester@"+srvB.addr() || len(saved.Rules) != 0 {
		t.Fatalf("saved %+v", saved)
	}
	if got := get(t, proxyClient("http://"+proxy, nil), o.URL+"/one"); got != "hello /one" {
		t.Fatalf("got %q", got)
	}
}

func TestEngineKeepsRunningSetupWhenAChangeFails(t *testing.T) {
	o := origin(t, false)
	e, proxy := testEngine(t, (&scriptedPrompt{}).prompt, origin(t, false).URL)
	addServer(t, e, "a")
	srv := newTestServer(t)
	// No password can be given: the SSH login fails and nothing changes.
	err := e.modify(func(cfg *appConfig) error {
		cfg.Proxies["b"] = proxySource{SSH: "tester@" + srv.addr(), Identity: "/nonexistent"}
		return nil
	})
	if err == nil {
		t.Fatal("want a login error")
	}
	if cfg, _ := loadAppConfig(e.path); len(cfg.Proxies) != 1 {
		t.Fatalf("failed source was saved: %+v", cfg.Proxies)
	}
	if got := get(t, proxyClient("http://"+proxy, nil), o.URL+"/still"); got != "hello /still" {
		t.Fatalf("got %q", got)
	}
	if err := e.setRouting(nil, "nosuch"); err == nil {
		t.Fatal("bad rules accepted")
	}
}

func panelRequest(t *testing.T, p *panel, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, "http://127.0.0.1:7890"+path, &buf)
	req.Header.Set("X-Token", token)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	return w
}

func TestPanelSecurity(t *testing.T) {
	e, _ := testEngine(t, (&scriptedPrompt{}).prompt, "http://127.0.0.1:1")
	p := newPanel(e, "127.0.0.1:7890", &uiPrompter{})

	if w := panelRequest(t, p, "GET", "/api/state", "wrong", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", w.Code)
	}
	if w := panelRequest(t, p, "GET", "/ui/", "", nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<title>sshproxy") {
		t.Fatalf("ui: %d", w.Code)
	}
	req := httptest.NewRequest("GET", "http://evil.example.com/api/state", nil)
	req.Header.Set("X-Token", p.token)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("foreign Host: %d", w.Code)
	}
	// A fresh start has no logs or sources yet; the panel needs [] not null.
	if body := panelRequest(t, p, "GET", "/api/state", p.token, nil).Body.String(); strings.Contains(body, "null") {
		t.Fatalf("state has null: %s", body)
	}
	if !strings.HasSuffix(p.url(), "/ui/#"+p.token) {
		t.Fatalf("url %q", p.url())
	}
}

func TestPanelPromptsForSSHPassword(t *testing.T) {
	o := origin(t, false)
	srv := newTestServer(t)
	prompter := &uiPrompter{}
	e, proxy := testEngine(t, prompter.prompt, o.URL)
	p := newPanel(e, proxy, prompter)

	// Without a password in the form, the login asks once the server is added.
	host, port, _ := net.SplitHostPort(srv.addr())
	added := make(chan error, 1)
	go func() {
		w := panelRequest(t, p, "POST", "/api/ssh", p.token, sshForm{Host: host, Port: port, User: "tester", Identity: "/nonexistent", Name: "box"})
		if w.Code != http.StatusOK {
			added <- fmt.Errorf("add: %d %s", w.Code, w.Body)
			return
		}
		added <- nil
	}()

	// The panel shows the question; answer it like the browser would.
	var st panelState
	eventually(t, "the password prompt", func() bool {
		json.Unmarshal(panelRequest(t, p, "GET", "/api/state", p.token, nil).Body.Bytes(), &st)
		return st.Prompt != nil
	})
	if !st.Prompt.Secret || !strings.Contains(st.Prompt.Text, "Password for tester@127.0.0.1") {
		t.Fatalf("prompt %+v", st.Prompt)
	}
	if w := panelRequest(t, p, "POST", "/api/prompt", p.token, map[string]any{"id": st.Prompt.ID, "answer": "secret"}); w.Code != http.StatusOK {
		t.Fatalf("answer: %d %s", w.Code, w.Body)
	}
	select {
	case err := <-added:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("add did not finish")
	}
	if got := get(t, proxyClient("http://"+proxy, nil), o.URL+"/ssh"); got != "hello /ssh" {
		t.Fatalf("got %q", got)
	}
	json.Unmarshal(panelRequest(t, p, "GET", "/api/state", p.token, nil).Body.Bytes(), &st)
	if len(st.Sources) != 1 || st.Sources[0].Kind != "ssh" || st.Sources[0].Status != "up" {
		t.Fatalf("sources %+v", st.Sources)
	}
}

func TestPromptCancel(t *testing.T) {
	u := &uiPrompter{}
	done := make(chan error, 1)
	go func() {
		_, err := u.prompt("Password: ", false)
		done <- err
	}()
	eventually(t, "the question", func() bool { return u.pending() != nil })
	id := u.pending().id
	if !u.answer(id, "", true) || u.answer(id, "", true) {
		t.Fatal("answer should succeed once")
	}
	if err := <-done; err != errPromptCanceled {
		t.Fatalf("err = %v", err)
	}
}

func TestEngineConfigEditing(t *testing.T) {
	e, _ := testEngine(t, (&scriptedPrompt{}).prompt, origin(t, false).URL)
	a, b := "a", "b"
	addServer(t, e, a)
	addServer(t, e, b)

	// Chains and routing reference the sources by name.
	if err := e.putGroup("main", policyFallback, []string{a, b}); err != nil {
		t.Fatal(err)
	}
	rules := []ruleSpec{{Match: "domain", Value: "corp.example.com", Out: a}, {Match: "ip", Value: "10.0.0.0/8", Out: "main"}}
	if err := e.setRouting(rules, outDirect); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []ruleSpec{
		{Match: "ip", Value: "example.com", Out: a},
		{Match: "domain", Value: "10.0.0.1", Out: a},
		{Match: "domain", Value: "", Out: a},
		{Match: "domain", Value: "ok.com", Out: "nosuch"},
	} {
		if err := e.setRouting([]ruleSpec{bad}, outDirect); err == nil || !strings.HasPrefix(err.Error(), "rule 1:") {
			t.Errorf("%+v: err = %v", bad, err)
		}
	}
	if err := e.setPin("main", b); err != nil {
		t.Fatal(err)
	}
	if _, _, current := e.app.byName["main"].snapshot(); current != b {
		t.Fatalf("pin not applied: current %q", current)
	}

	// Renaming follows every reference, including the pin.
	if err := e.rename(a, "tokyo"); err != nil {
		t.Fatal(err)
	}
	if err := e.rename(b, "tokyo"); err == nil {
		t.Fatal("duplicate name accepted")
	}
	if err := e.rename(b, outFastest); err == nil {
		t.Fatal("reserved name accepted")
	}
	if err := e.rename(b, "osaka"); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadAppConfig(e.path)
	if err != nil {
		t.Fatal(err)
	}
	gotRules, def := toRuleSpecs(cfg.Rules)
	wantRules := []ruleSpec{{Match: "domain", Value: "corp.example.com", Out: "tokyo"}, {Match: "ip", Value: "10.0.0.0/8", Out: "main"}}
	if !slices.Equal(gotRules, wantRules) || def != outDirect {
		t.Fatalf("rules %+v default %q", gotRules, def)
	}
	if !slices.Equal(cfg.Groups["main"].Members, []string{"tokyo", "osaka"}) || cfg.Pins["main"] != "osaka" {
		t.Fatalf("groups %+v pins %+v", cfg.Groups, cfg.Pins)
	}
	if e.app.byName["main"].pin() != "osaka" {
		t.Fatal("pin lost after reload")
	}

	// Deleting the chain removes its rule and pin.
	if err := e.deleteGroup("main"); err != nil {
		t.Fatal(err)
	}
	cfg, _ = loadAppConfig(e.path)
	if gotRules, _ := toRuleSpecs(cfg.Rules); len(gotRules) != 1 || len(cfg.Pins) != 0 {
		t.Fatalf("after delete: rules %+v pins %+v", gotRules, cfg.Pins)
	}

	// No rules and "fastest" for everything else leaves the config rule-free.
	if err := e.setRouting(nil, outFastest); err != nil {
		t.Fatal(err)
	}
	cfg, _ = loadAppConfig(e.path)
	if len(cfg.Rules) != 0 {
		t.Fatalf("rules %+v", cfg.Rules)
	}
}

func TestSSHOptionsAreSaved(t *testing.T) {
	e, _ := testEngine(t, (&scriptedPrompt{answers: []string{"secret", "secret"}}).prompt, origin(t, false).URL)
	name := "box"
	addServer(t, e, name)
	if err := e.setSSHOptions(name, "/nonexistent-key", ""); err != nil {
		t.Fatal(err)
	}
	cfg, _ := loadAppConfig(e.path)
	if cfg.Proxies[name].Identity != "/nonexistent-key" || cfg.Proxies[name].SSH == "" {
		t.Fatalf("saved %+v", cfg.Proxies[name])
	}
}

func TestAddSSHFromForm(t *testing.T) {
	srv := newTestServer(t)
	prompt := &scriptedPrompt{} // the form must never cause a prompt
	e, proxy := testEngine(t, prompt.prompt, origin(t, false).URL)
	host, port, _ := net.SplitHostPort(srv.addr())

	form := sshForm{Host: host, Port: port, User: "tester", Password: "wrong", Identity: "/nonexistent"}
	if _, err := e.addSSH(form); err == nil || !strings.Contains(err.Error(), "login rejected") {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := e.addSSH(sshForm{Host: "127.0.0.1", Port: "1", User: "tester", Password: "x"}); err == nil ||
		!strings.Contains(err.Error(), "can't reach") {
		t.Fatalf("unreachable: %v", err)
	}
	if _, err := e.addSSH(sshForm{Host: host, Port: "99999"}); err == nil {
		t.Fatal("bad port accepted")
	}

	form.Password, form.Name = "secret", "office"
	name, err := e.addSSH(form)
	if err != nil {
		t.Fatal(err)
	}
	if name != "office" || prompt.count() != 0 {
		t.Fatalf("name %q, prompts %d", name, prompt.count())
	}
	o := origin(t, false)
	if got := get(t, proxyClient("http://"+proxy, nil), o.URL+"/f"); got != "hello /f" {
		t.Fatalf("got %q", got)
	}
	cfg, _ := e.load()
	if p := cfg.Proxies["office"]; p.SSH != "tester@"+srv.addr() || p.Identity != "/nonexistent" {
		t.Fatalf("saved %+v", p)
	}
	if data, _ := os.ReadFile(e.path); strings.Contains(string(data), "secret") {
		t.Fatal("password written to the config file")
	}
}

// fakeAutostart records login item changes instead of touching the OS.
type fakeAutostart struct{ on bool }

func (f *fakeAutostart) IsEnabled() (bool, error) { return f.on, nil }
func (f *fakeAutostart) Enable() error            { f.on = true; return nil }
func (f *fakeAutostart) Disable() error           { f.on = false; return nil }

func TestPanelAutostart(t *testing.T) {
	e, _ := testEngine(t, (&scriptedPrompt{}).prompt, "http://127.0.0.1:1")
	p := newPanel(e, "127.0.0.1:7890", &uiPrompter{})

	// Builds without a desktop shell don't offer it.
	if body := panelRequest(t, p, "GET", "/api/state", p.token, nil).Body.String(); strings.Contains(body, `"autostart"`) {
		t.Fatalf("autostart offered without support: %s", body)
	}
	if w := panelRequest(t, p, "POST", "/api/autostart", p.token, map[string]bool{"enabled": true}); w.Code != http.StatusBadRequest {
		t.Fatalf("unsupported enable: %d", w.Code)
	}

	fake := &fakeAutostart{}
	p.autostart = fake
	if w := panelRequest(t, p, "POST", "/api/autostart", p.token, map[string]bool{"enabled": true}); w.Code != http.StatusOK || !fake.on {
		t.Fatalf("enable: %d %v", w.Code, fake.on)
	}
	var st panelState
	json.Unmarshal(panelRequest(t, p, "GET", "/api/state", p.token, nil).Body.Bytes(), &st)
	if st.Autostart == nil || !*st.Autostart {
		t.Fatalf("state autostart = %v", st.Autostart)
	}
}

func TestRememberSystemProxy(t *testing.T) {
	e, _ := testEngine(t, (&scriptedPrompt{}).prompt, "http://127.0.0.1:1")
	addServer(t, e, "a")
	if err := e.rememberSystemProxy(true); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadAppConfig(e.path)
	if err != nil || !cfg.SystemProxy || len(cfg.Proxies) != 1 {
		t.Fatalf("saved %+v %v", cfg, err)
	}
	if err := e.rememberSystemProxy(false); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(e.path); strings.Contains(string(data), "system_proxy") {
		t.Fatalf("off should leave no setting:\n%s", data)
	}
}

func TestSSHFormUsesSSHConfig(t *testing.T) {
	cfg, err := ssh_config.Decode(strings.NewReader(`
Host gcp-*
  User deploy
Host gcp-hk-01
  HostName 10.0.0.9
  Port 2200
`))
	if err != nil {
		t.Fatal(err)
	}
	e, _ := testEngine(t, (&scriptedPrompt{}).prompt, "http://127.0.0.1:1")
	e.sshCfg = cfg
	// Empty fields come from ~/.ssh/config, then defaults; the server field
	// takes a whole user@host:port, and separate fields win over it.
	for _, tc := range []struct {
		form sshForm
		want string
	}{
		{sshForm{Host: "gcp-hk-01"}, "deploy@10.0.0.9:2200"},
		{sshForm{Host: "gcp-hk-01", Port: "22", User: "root"}, "root@10.0.0.9:22"},
		{sshForm{Host: "admin@gcp-hk-01:2022"}, "admin@10.0.0.9:2022"},
		{sshForm{Host: "admin@gcp-hk-01:2022", User: "root"}, "root@10.0.0.9:2022"},
		{sshForm{Host: "1.2.3.4"}, currentUser() + "@1.2.3.4:22"},
	} {
		_, d, err := e.formDest(tc.form)
		if err != nil || d.String() != tc.want {
			t.Errorf("%+v: got %v %v, want %s", tc.form, d, err, tc.want)
		}
	}
	if _, _, err := e.formDest(sshForm{Host: "x", Port: "abc"}); err == nil {
		t.Fatal("bad port accepted")
	}
}

// The desktop app's web view doesn't implement alert / confirm / prompt
// (confirm silently returns false), so the panel must use its own dialogs.
func TestPanelUsesNoBrowserDialogs(t *testing.T) {
	page, err := uiFiles.ReadFile("ui/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if m := regexp.MustCompile(`\b(alert|confirm|prompt)\(`).Find(page); m != nil {
		t.Fatalf("ui/index.html calls %s; use dialog() instead", m)
	}
}

func TestPanelCheck(t *testing.T) {
	probe := origin(t, false)
	e, addr := testEngine(t, (&scriptedPrompt{}).prompt, probe.URL)
	addServer(t, e, "a")
	p := newPanel(e, addr, &uiPrompter{})
	var res checkResult
	json.Unmarshal(panelRequest(t, p, "POST", "/api/check", p.token, nil).Body.Bytes(), &res)
	if !res.OK || res.Error != "" {
		t.Fatalf("check through a working proxy: %+v", res)
	}

	e.hc.url = "http://127.0.0.1:1/"
	json.Unmarshal(panelRequest(t, p, "POST", "/api/check", p.token, nil).Body.Bytes(), &res)
	if res.OK || !strings.Contains(res.Error, "502") {
		t.Fatalf("check of an unreachable site: %+v", res)
	}
}

// The panel's Test asks for checkHost through whatever proxy the page uses;
// only sshproxy answers it.
func TestCheckHostAnsweredByProxy(t *testing.T) {
	_, addr := testEngine(t, (&scriptedPrompt{}).prompt, "http://127.0.0.1:1")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: addr})}}
	resp, err := client.Get("http://" + checkHost + "/?1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("got %s %v", resp.Status, resp.Header)
	}
}

func TestPanelReportsSystemProxyFailure(t *testing.T) {
	e, _ := testEngine(t, (&scriptedPrompt{}).prompt, "http://127.0.0.1:1")
	p := newPanel(e, "127.0.0.1:7890", &uiPrompter{})
	p.proxyErr = "no desktop"
	var st panelState
	json.Unmarshal(panelRequest(t, p, "GET", "/api/state", p.token, nil).Body.Bytes(), &st)
	if st.ProxyError != "no desktop" {
		t.Fatalf("state error = %q", st.ProxyError)
	}
}
