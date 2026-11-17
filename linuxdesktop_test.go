package main

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// fakeDesktop records commands and keeps gsettings / kioslaverc in maps.
type fakeDesktop struct {
	tools map[string]bool
	gnome map[string]string // "schema key" -> value
	kde   map[string]string // key -> value
	calls []string
}

func (f *fakeDesktop) linux() linuxDesktops {
	return linuxDesktops{
		look: func(name string) (string, error) {
			if f.tools[name] {
				return "/usr/bin/" + name, nil
			}
			return "", errors.New("not found")
		},
		run: func(name string, args ...string) (string, error) {
			f.calls = append(f.calls, name+" "+strings.Join(args, " "))
			switch {
			case name == "gsettings" && args[0] == "set":
				f.gnome[args[1]+" "+args[2]] = args[3]
			case name == "gsettings" && args[0] == "get":
				return "'" + f.gnome[args[1]+" "+args[2]] + "'\n", nil
			case strings.HasPrefix(name, "kwriteconfig"):
				f.kde[args[5]] = args[6]
			case strings.HasPrefix(name, "kreadconfig"):
				return f.kde[args[5]] + "\n", nil
			}
			return "", nil
		},
	}
}

func newFakeDesktop(tools ...string) *fakeDesktop {
	f := &fakeDesktop{tools: map[string]bool{}, gnome: map[string]string{}, kde: map[string]string{}}
	for _, t := range tools {
		f.tools[t] = true
	}
	return f
}

func TestLinuxGNOME(t *testing.T) {
	f := newFakeDesktop("gsettings")
	l := f.linux()
	if err := l.set("127.0.0.1:7890"); err != nil {
		t.Fatal(err)
	}
	if f.gnome["org.gnome.system.proxy mode"] != "manual" || f.gnome["org.gnome.system.proxy.https host"] != "127.0.0.1" ||
		f.gnome["org.gnome.system.proxy.socks port"] != "7890" {
		t.Fatalf("gsettings %v", f.gnome)
	}
	if !l.isSet("127.0.0.1:7890") || l.isSet("127.0.0.1:7891") {
		t.Fatal("isSet wrong")
	}
	if err := l.clear("127.0.0.1:7890"); err != nil || f.gnome["org.gnome.system.proxy mode"] != "none" {
		t.Fatalf("clear: %v %v", err, f.gnome)
	}
}

func TestLinuxKDE(t *testing.T) {
	f := newFakeDesktop("kwriteconfig6", "kreadconfig6", "dbus-send")
	l := f.linux()
	if err := l.set("127.0.0.1:7890"); err != nil {
		t.Fatal(err)
	}
	if f.kde["ProxyType"] != "1" || f.kde["httpProxy"] != "http://127.0.0.1 7890" || f.kde["socksProxy"] != "socks://127.0.0.1 7890" {
		t.Fatalf("kioslaverc %v", f.kde)
	}
	if !slices.ContainsFunc(f.calls, func(c string) bool { return strings.Contains(c, "reparseSlaveConfiguration") }) {
		t.Fatal("KDE not told to reload")
	}
	if !l.isSet("127.0.0.1:7890") {
		t.Fatal("isSet = false")
	}
	if err := l.clear("127.0.0.1:7890"); err != nil || f.kde["ProxyType"] != "0" {
		t.Fatalf("clear: %v %v", err, f.kde)
	}
}

func TestLinuxBothAndNeither(t *testing.T) {
	f := newFakeDesktop("gsettings", "kwriteconfig5", "kreadconfig5")
	if err := f.linux().set("127.0.0.1:7890"); err != nil {
		t.Fatal(err)
	}
	if f.gnome["org.gnome.system.proxy mode"] != "manual" || f.kde["ProxyType"] != "1" {
		t.Fatal("both desktops should be set")
	}

	// Someone else's proxy is left alone.
	f = newFakeDesktop("gsettings", "kwriteconfig5", "kreadconfig5")
	f.gnome["org.gnome.system.proxy mode"] = "manual"
	f.gnome["org.gnome.system.proxy.http host"] = "10.0.0.1"
	f.gnome["org.gnome.system.proxy.http port"] = "3128"
	f.kde["ProxyType"], f.kde["httpProxy"] = "1", "http://10.0.0.1 3128"
	f.linux().clear("127.0.0.1:7890")
	if f.gnome["org.gnome.system.proxy mode"] != "manual" || f.kde["ProxyType"] != "1" {
		t.Fatal("cleared a proxy that wasn't ours")
	}

	if err := newFakeDesktop().linux().set("127.0.0.1:7890"); !errors.Is(err, errNoDesktop) {
		t.Fatalf("err = %v", err)
	}
}
