package main

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

//go:embed ui
var uiFiles embed.FS

// panel serves the control panel and its API on the proxy port.
type panel struct {
	e      *engine
	addr   string // proxy address, for the system proxy
	token  string
	prompt *uiPrompter
	mux    *http.ServeMux

	// autostart controls starting at login; nil where it isn't supported.
	autostart autostarter

	mu          sync.Mutex
	systemProxy bool   // set by us
	proxyErr    string // why switching it on last failed
}

func newPanel(e *engine, addr string, prompt *uiPrompter) *panel {
	b := make([]byte, 16)
	rand.Read(b)
	p := &panel{e: e, addr: addr, token: hex.EncodeToString(b), prompt: prompt, mux: http.NewServeMux()}
	p.mux.Handle("GET /ui/", http.FileServerFS(uiFiles))
	p.mux.HandleFunc("GET /ui", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusFound)
	})
	p.api("GET /api/state", p.state)
	p.api("POST /api/ssh", p.addSSH)
	p.api("DELETE /api/sources/{name}", p.removeSource)
	p.api("PUT /api/routing", p.setRouting)
	p.api("POST /api/rename", p.rename)
	p.api("PUT /api/sources/{name}/ssh", p.setSSHOptions)
	p.api("PUT /api/groups/{name}", p.putGroup)
	p.api("DELETE /api/groups/{name}", p.deleteGroup)
	p.api("PUT /api/pins/{group}", p.setPin)
	p.api("POST /api/system-proxy", p.setSystemProxy)
	p.api("POST /api/check", p.check)
	p.api("POST /api/autostart", p.setAutostart)
	p.api("POST /api/prompt", p.answerPrompt)
	return p
}

// url is what the tray opens; the token travels in the fragment, which the
// browser never sends to a server.
func (p *panel) url() string {
	return "http://" + p.addr + "/ui/#" + p.token
}

// handles reports whether a non-proxy request is for the panel.
func (p *panel) handles(r *http.Request) bool {
	return r.URL.Path == "/ui" || strings.HasPrefix(r.URL.Path, "/ui/") || strings.HasPrefix(r.URL.Path, "/api/")
}

func (p *panel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only loopback host names, so DNS rebinding can't reach the API.
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	if ip := net.ParseIP(host); !(host == "localhost" || ip != nil && ip.IsLoopback()) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	p.mux.ServeHTTP(w, r)
}

// api registers a JSON handler that requires the token.
func (p *panel) api(pattern string, h func(r *http.Request) (any, error)) {
	p.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Token")), []byte(p.token)) != 1 {
			http.Error(w, "missing or wrong token; reopen the panel from the tray icon", http.StatusUnauthorized)
			return
		}
		v, err := h(r)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			v = map[string]string{"error": err.Error()}
		}
		json.NewEncoder(w).Encode(v)
	})
}

func decodeBody(r *http.Request, v any) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return errors.New("bad request body")
	}
	return nil
}

// UI state, as JSON.
type (
	panelState struct {
		Proxy       string         `json:"proxy"`
		ConfigPath  string         `json:"configPath"`
		SystemProxy bool           `json:"systemProxy"`
		ProxyError  string         `json:"systemProxyError,omitempty"`
		Autostart   *bool          `json:"autostart,omitempty"` // nil: not available in this build
		Loading     bool           `json:"loading"`
		Error       string         `json:"error,omitempty"`
		Sources     []sourceState  `json:"sources"`
		Groups      []sourceState  `json:"groups"`
		Routing     routingState   `json:"routing"`
		Outbounds   []outboundInfo `json:"outbounds"` // choices for rules and chains
		Prompt      *promptState   `json:"prompt,omitempty"`
		Logs        []string       `json:"logs"`
	}
	sourceState struct {
		Name    string      `json:"name"`
		Kind    string      `json:"kind"`
		Detail  string      `json:"detail,omitempty"`
		Status  string      `json:"status"` // up, down, unknown
		Latency int64       `json:"latencyMs,omitempty"`
		Current string      `json:"current,omitempty"`
		Pinned  string      `json:"pinned,omitempty"`
		Nodes   []nodeState `json:"nodes,omitempty"`
		// SSH sources
		Target   string `json:"target,omitempty"`
		Identity string `json:"identity,omitempty"`
		Jump     string `json:"jump,omitempty"`
	}
	routingState struct {
		Rules   []ruleSpec `json:"rules"`
		Default string     `json:"default"`
	}
	outboundInfo struct {
		Name   string `json:"name"`
		Kind   string `json:"kind"`
		Status string `json:"status"`
	}
	nodeState struct {
		Name    string `json:"name"`
		Status  string `json:"status"`
		Latency int64  `json:"latencyMs,omitempty"`
	}
	promptState struct {
		ID     int    `json:"id"`
		Text   string `json:"text"`
		Secret bool   `json:"secret"`
	}
)

func memberStatus(m member) (string, int64) {
	lat := m.latency().Milliseconds()
	switch {
	case !m.healthy():
		return "down", 0
	case lat > 0:
		return "up", lat
	}
	if _, isGroup := m.(*group); isGroup {
		return "up", 0 // some member works
	}
	if l, ok := m.(*leaf); ok {
		if _, isConn := l.out.(connector); isConn {
			return "up", 0 // connected SSH
		}
	}
	return "unknown", 0
}

func describe(s appSource) sourceState {
	st := sourceState{Name: s.name, Kind: s.kind, Detail: s.detail}
	st.Status, st.Latency = memberStatus(s.m)
	if g, ok := s.m.(*group); ok {
		names, members, current := g.snapshot()
		st.Current, st.Pinned = current, g.pin()
		for i, m := range members {
			n := nodeState{Name: names[i]}
			n.Status, n.Latency = memberStatus(m)
			st.Nodes = append(st.Nodes, n)
		}
	}
	return st
}

func (p *panel) state(*http.Request) (any, error) {
	e := p.e
	e.mu.Lock()
	cfg, a, err, loading := e.cfg, e.app, e.err, e.loading
	e.mu.Unlock()
	st := panelState{
		Proxy:       p.addr,
		ConfigPath:  e.path,
		SystemProxy: p.systemProxyOn(),
		ProxyError:  p.systemProxyError(),
		Loading:     loading,
		Sources:     []sourceState{},
		Groups:      []sourceState{},
		Routing:     routingState{Rules: []ruleSpec{}, Default: outFastest},
		Outbounds:   []outboundInfo{},
		Logs:        e.logs.recent(),
	}
	if err != nil {
		st.Error = err.Error()
	}
	if p.autostart != nil {
		on, _ := p.autostart.IsEnabled()
		st.Autostart = &on
	}
	if a != nil {
		for _, src := range a.sources {
			d := describe(src)
			if cfg != nil && src.kind == "ssh" {
				ps := cfg.Proxies[src.name]
				d.Target, d.Identity, d.Jump = ps.SSH, ps.Identity, ps.Jump
			}
			st.Sources = append(st.Sources, d)
			st.Outbounds = append(st.Outbounds, outboundInfo{Name: d.Name, Kind: d.Kind, Status: d.Status})
		}
		for _, g := range a.groups {
			d := describe(g)
			st.Groups = append(st.Groups, d)
			if g.name != outFastest {
				st.Outbounds = append(st.Outbounds, outboundInfo{Name: d.Name, Kind: "chain", Status: d.Status})
			}
		}
	}
	// "fastest" always exists as a choice (with no sources it is just
	// where traffic will go once one is added).
	fastest := outboundInfo{Name: outFastest, Kind: "built-in", Status: "unknown"}
	if a != nil && a.byName[outFastest] != nil {
		fastest.Status, _ = memberStatus(a.byName[outFastest])
	}
	st.Outbounds = append(st.Outbounds, fastest)
	st.Outbounds = append(st.Outbounds, outboundInfo{Name: outDirect, Kind: "built-in", Status: "up"})
	if cfg != nil {
		st.Routing.Rules, st.Routing.Default = toRuleSpecs(cfg.Rules)
	}
	if pr := p.prompt.pending(); pr != nil {
		st.Prompt = &promptState{ID: pr.id, Text: pr.text, Secret: pr.secret}
	}
	return st, nil
}

func (p *panel) addSSH(r *http.Request) (any, error) {
	var req sshForm
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	name, err := p.e.addSSH(req)
	return map[string]string{"name": name}, err
}

func (p *panel) removeSource(r *http.Request) (any, error) {
	return struct{}{}, p.e.removeSource(r.PathValue("name"))
}

func (p *panel) setRouting(r *http.Request) (any, error) {
	var req routingState
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	return struct{}{}, p.e.setRouting(req.Rules, req.Default)
}

func (p *panel) rename(r *http.Request) (any, error) {
	var req struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	return struct{}{}, p.e.rename(req.From, req.To)
}

func (p *panel) setSSHOptions(r *http.Request) (any, error) {
	var req struct {
		Identity string `json:"identity"`
		Jump     string `json:"jump"`
	}
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	return struct{}{}, p.e.setSSHOptions(r.PathValue("name"), req.Identity, req.Jump)
}

func (p *panel) putGroup(r *http.Request) (any, error) {
	var req struct {
		Policy  string   `json:"policy"`
		Members []string `json:"members"`
	}
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	return struct{}{}, p.e.putGroup(r.PathValue("name"), req.Policy, req.Members)
}

func (p *panel) deleteGroup(r *http.Request) (any, error) {
	return struct{}{}, p.e.deleteGroup(r.PathValue("name"))
}

func (p *panel) setPin(r *http.Request) (any, error) {
	var req struct {
		Member string `json:"member"`
	}
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	return struct{}{}, p.e.setPin(r.PathValue("group"), req.Member)
}

func (p *panel) setSystemProxy(r *http.Request) (any, error) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	return struct{}{}, p.switchSystemProxy(req.Enabled)
}

// autostarter registers the app to start at login.
type autostarter interface {
	IsEnabled() (bool, error)
	Enable() error
	Disable() error
}

func (p *panel) setAutostart(r *http.Request) (any, error) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	return struct{}{}, p.switchAutostart(req.Enabled)
}

// switchAutostart turns starting at login on or off.
func (p *panel) switchAutostart(on bool) error {
	if p.autostart == nil {
		return errors.New("starting at login is only available in the desktop app")
	}
	var err error
	if on {
		err = p.autostart.Enable()
	} else {
		err = p.autostart.Disable()
	}
	if err != nil {
		return fmt.Errorf("start at login: %w", err)
	}
	p.e.logs.logf("Start at login %s", map[bool]string{true: "on", false: "off"}[on])
	return nil
}

// switchSystemProxy turns the OS proxy setting on or off and remembers the
// choice for the next start.
func (p *panel) switchSystemProxy(on bool) error {
	if err := p.applySystemProxy(on); err != nil {
		return err
	}
	return p.e.rememberSystemProxy(on)
}

// applySystemProxy changes the OS proxy setting only.
func (p *panel) applySystemProxy(on bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var err error
	if on {
		err = setSystemProxy(p.addr)
	} else {
		err = clearSystemProxy(p.addr)
	}
	p.proxyErr = ""
	if err == nil {
		p.systemProxy = on
		p.e.logs.logf("System proxy %s", map[bool]string{true: "on", false: "off"}[on])
	} else if on {
		p.proxyErr = err.Error()
	}
	return err
}

func (p *panel) systemProxyOn() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.systemProxy
}

func (p *panel) systemProxyError() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.proxyErr
}

// checkResult is what the panel's Test button reports.
type checkResult struct {
	OK        bool   `json:"ok"`        // a request through sshproxy got through
	LatencyMs int64  `json:"latencyMs"` // how long it took
	Error     string `json:"error,omitempty"`
	// SettingsSet tells whether the OS proxy settings point at sshproxy.
	SettingsSet bool `json:"settingsSet"`
}

// check sends a request through sshproxy's own port, the way any app would,
// and looks at whether the OS proxy settings point at it.
func (p *panel) check(r *http.Request) (any, error) {
	res := checkResult{SettingsSet: systemProxyIsSet(p.addr)}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: p.addr})},
		Timeout:   10 * time.Second,
	}
	start := time.Now()
	resp, err := client.Get(p.e.hc.url)
	if err == nil {
		// sshproxy reports upstream failures as 502 with the reason as body.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		if resp.StatusCode >= 400 {
			err = fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
	}
	if err != nil {
		res.Error = err.Error()
	} else {
		res.OK, res.LatencyMs = true, time.Since(start).Milliseconds()
	}
	return res, nil
}

func (p *panel) answerPrompt(r *http.Request) (any, error) {
	var req struct {
		ID     int    `json:"id"`
		Answer string `json:"answer"`
		Cancel bool   `json:"cancel"`
	}
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	if !p.prompt.answer(req.ID, req.Answer, req.Cancel) {
		return nil, errors.New("this question is no longer pending")
	}
	return struct{}{}, nil
}

// uiPrompter asks the questions SSH logins need (passwords, passphrases)
// in the control panel instead of a terminal.
type uiPrompter struct {
	ask     sync.Mutex // one question at a time
	mu      sync.Mutex
	nextID  int
	current *uiQuestion
	notify  func() // e.g. open the panel so the user sees the question
}

type uiQuestion struct {
	id     int
	text   string
	secret bool
	reply  chan uiAnswer
}

type uiAnswer struct {
	text   string
	cancel bool
}

var errPromptCanceled = errors.New("login canceled")

// promptTimeout bounds how long a login waits for the user.
var promptTimeout = 5 * time.Minute

func (u *uiPrompter) prompt(text string, echo bool) (string, error) {
	u.ask.Lock()
	defer u.ask.Unlock()
	u.mu.Lock()
	u.nextID++
	q := &uiQuestion{id: u.nextID, text: text, secret: !echo, reply: make(chan uiAnswer, 1)}
	u.current = q
	notify := u.notify
	u.mu.Unlock()
	defer func() {
		u.mu.Lock()
		u.current = nil
		u.mu.Unlock()
	}()
	if notify != nil {
		notify()
	}
	select {
	case a := <-q.reply:
		if a.cancel {
			return "", errPromptCanceled
		}
		return a.text, nil
	case <-time.After(promptTimeout):
		return "", errors.New("nobody answered the login prompt")
	}
}

func (u *uiPrompter) pending() *uiQuestion {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.current
}

func (u *uiPrompter) answer(id int, text string, cancel bool) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.current == nil || u.current.id != id {
		return false
	}
	u.current.reply <- uiAnswer{text: text, cancel: cancel}
	u.current = nil // a second answer must not block
	return true
}
