## Desktop app

| Computer | File |
|---|---|
| Mac with Apple chip | `sshproxy-macos-arm64.zip` |
| Mac with Intel chip | `sshproxy-macos-amd64.zip` |
| Windows | `sshproxy-windows-amd64.exe` |
| Windows on ARM | `sshproxy-windows-arm64.exe` |
| Linux | `sshproxy-linux-amd64`, `sshproxy-linux-arm64` |

The apps aren't code-signed, so macOS and Windows warn the first time; the [README](https://github.com/zzn01/sshproxy#2-open-it) explains how to open them.

## Command line

`sshproxy-cli-<os>-<arch>`, for example `sshproxy-cli-linux-amd64`. Rename it to `sshproxy` and put it on your `PATH`. See [Command line](https://github.com/zzn01/sshproxy#command-line).
