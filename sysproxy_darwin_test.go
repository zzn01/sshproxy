package main

import (
	"slices"
	"strings"
	"testing"
)

func TestDarwinSystemProxyCommands(t *testing.T) {
	var calls []string
	state := map[string]string{} // "svc kind" -> output
	orig := runCmd
	t.Cleanup(func() { runCmd = orig })
	runCmd = func(name string, args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
		switch args[0] {
		case "-listallnetworkservices":
			return "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Bluetooth PAN\nUSB LAN\n", nil
		case "-getwebproxy", "-getsecurewebproxy", "-getsocksfirewallproxy":
			return state[args[1]+" "+args[0][4:]], nil
		}
		return "", nil
	}

	if err := setSystemProxy("127.0.0.1:7890"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"-setwebproxy Wi-Fi 127.0.0.1 7890",
		"-setsecurewebproxy USB LAN 127.0.0.1 7890",
		"-setsocksfirewallproxy Wi-Fi 127.0.0.1 7890",
	} {
		if !slices.Contains(calls, want) {
			t.Errorf("missing %q in %q", want, calls)
		}
	}
	if slices.ContainsFunc(calls, func(c string) bool { return strings.Contains(c, "Bluetooth") }) {
		t.Error("touched a disabled service")
	}

	enabled := "Enabled: Yes\nServer: 127.0.0.1\nPort: 7890\n"
	state["Wi-Fi webproxy"] = enabled
	state["Wi-Fi socksfirewallproxy"] = enabled
	state["USB LAN webproxy"] = "Enabled: Yes\nServer: 10.0.0.1\nPort: 3128\n" // the user's own proxy
	if !systemProxyIsSet("127.0.0.1:7890") {
		t.Fatal("systemProxyIsSet = false")
	}
	calls = nil
	clearSystemProxy("127.0.0.1:7890")
	off := slices.DeleteFunc(slices.Clone(calls), func(c string) bool { return !strings.HasSuffix(c, " off") })
	if want := []string{"-setwebproxystate Wi-Fi off", "-setsocksfirewallproxystate Wi-Fi off"}; !slices.Equal(off, want) {
		t.Fatalf("turned off %q, want %q", off, want)
	}
}
