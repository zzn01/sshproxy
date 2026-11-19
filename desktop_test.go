package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRunningPanel(t *testing.T) {
	e, _ := testEngine(t, (&scriptedPrompt{}).prompt, "http://127.0.0.1:1")
	p := newPanel(e, "127.0.0.1:7890", &uiPrompter{})
	srv := httptest.NewServer(p)
	dir := t.TempDir()
	write := func(content string) string {
		f := filepath.Join(dir, "panel-url")
		if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return f
	}

	url := srv.URL + "/ui/#" + p.token
	if got := runningPanel(write(url + "\n")); got != url {
		t.Fatalf("running panel: got %q", got)
	}
	if got := runningPanel(write(srv.URL + "/ui/#wrong")); got != "" {
		t.Fatalf("wrong token: got %q", got)
	}
	if got := runningPanel(write("garbage")); got != "" {
		t.Fatalf("garbage: got %q", got)
	}
	if got := runningPanel(filepath.Join(dir, "missing")); got != "" {
		t.Fatalf("missing file: got %q", got)
	}
	srv.Close()
	if got := runningPanel(write(url)); got != "" {
		t.Fatalf("stopped panel: got %q", got)
	}
}
