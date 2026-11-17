//go:build !darwin && !windows && !linux

package main

import "errors"

func setSystemProxy(string) error {
	return errors.New("setting the system proxy isn't supported on this OS")
}

func systemProxyIsSet(string) bool { return false }

func clearSystemProxy(string) error { return nil }
