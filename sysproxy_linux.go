package main

import (
	"os/exec"
	"strings"
)

var desktops = linuxDesktops{
	run: func(name string, args ...string) (string, error) {
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil && len(out) > 0 {
			return string(out), &commandError{name: name, out: strings.TrimSpace(string(out)), err: err}
		}
		return string(out), err
	},
	look: exec.LookPath,
}

type commandError struct {
	name, out string
	err       error
}

func (e *commandError) Error() string { return e.name + ": " + e.out }
func (e *commandError) Unwrap() error { return e.err }

func setSystemProxy(addr string) error   { return desktops.set(addr) }
func systemProxyIsSet(addr string) bool  { return desktops.isSet(addr) }
func clearSystemProxy(addr string) error { return desktops.clear(addr) }
