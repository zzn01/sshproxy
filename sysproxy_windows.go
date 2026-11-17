package main

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const internetSettings = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// Local addresses that should never go through the proxy.
const proxyOverride = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>"

func setSystemProxy(addr string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettings, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetStringValue("ProxyServer", addr); err != nil {
		return err
	}
	if err := k.SetStringValue("ProxyOverride", proxyOverride); err != nil {
		return err
	}
	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return err
	}
	refreshInternetSettings()
	return nil
}

func systemProxyIsSet(addr string) bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettings, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	enabled, _, _ := k.GetIntegerValue("ProxyEnable")
	server, _, _ := k.GetStringValue("ProxyServer")
	return enabled == 1 && server == addr
}

// clearSystemProxy turns the proxy off only if it points at addr.
func clearSystemProxy(addr string) error {
	if !systemProxyIsSet(addr) {
		return nil
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettings, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetDWordValue("ProxyEnable", 0); err != nil {
		return err
	}
	refreshInternetSettings()
	return nil
}

// refreshInternetSettings tells running programs that the settings changed.
func refreshInternetSettings() {
	const (
		optionSettingsChanged = 39
		optionRefresh         = 37
	)
	proc := windows.NewLazySystemDLL("wininet.dll").NewProc("InternetSetOptionW")
	proc.Call(0, optionSettingsChanged, 0, 0)
	proc.Call(0, optionRefresh, 0, 0)
}
