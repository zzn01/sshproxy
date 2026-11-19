# sshproxy

If you have a server you can log in to with SSH (for example a cloud
server you rent), sshproxy lets your computer use the internet through
that server. You don't install anything on the server. You only need its
address, a username and a password (or key), the same details you'd use
to log in to it.

There are two versions:

- **Desktop app**: a normal app with a window and an on/off switch. Start
  here if you don't use a terminal.
- **Command line**: for people who use a terminal, see
  [Command line](#command-line).

## Desktop app

### 1. Get the file for your computer

Download it from the
[releases page](https://github.com/zzn01/sshproxy/releases).

| Computer | File |
|---|---|
| Mac with Apple chip (M1, M2, …) | `sshproxy-macos-arm64.zip` |
| Mac with Intel chip | `sshproxy-macos-amd64.zip` |
| Windows (most PCs) | `sshproxy-windows-amd64.exe` |
| Windows on ARM (e.g. Snapdragon laptops) | `sshproxy-windows-arm64.exe` |
| Linux | `sshproxy-linux-amd64` or `sshproxy-linux-arm64` |

Not sure which Mac you have? Apple menu → **About This Mac**, look at
"Chip" or "Processor".

### 2. Open it

The app isn't signed by Apple or Microsoft, so your computer warns you the
first time. This is expected.

- **Mac**: unzip the file and double-click `sshproxy.app`. When macOS
  refuses to open it, go to **System Settings → Privacy & Security**,
  scroll down and click **Open Anyway**. Moving the app to the
  Applications folder is optional.
- **Windows**: double-click the file. If a blue "Windows protected your
  PC" box appears, click **More info → Run anyway**.
- **Linux**: make the file executable (right-click → Properties →
  Permissions, or `chmod +x`) and run it. On older systems (before
  Ubuntu 24.04, Debian 13 or Fedora 39) sshproxy opens in your web browser
  instead of its own window; everything works the same. If you close the
  browser tab, open sshproxy again to get it back.

The first time, the sshproxy window opens by itself. After that sshproxy
lives in the menu bar (Mac) or the system tray (Windows, Linux): click its
icon and choose **Open sshproxy** to show the window.

On Linux the tray icon needs a desktop that shows app indicators: KDE,
Ubuntu, Cinnamon and most others do. Plain GNOME (e.g. Fedora) needs the
"AppIndicator and KStatusNotifierItem Support" extension
(`sudo dnf install gnome-shell-extension-appindicator`, then log out and
back in). Without it there is no icon; to get the window back, open
sshproxy again.

### 3. Add your server

1. Click **Add server**.
2. Type your server as `username@address`, for example `root@1.2.3.4`.
   If the server uses a port other than 22, add it at the end:
   `root@1.2.3.4:2222`.
3. Click **Connect**. When asked, type the server's password and click
   **Log in**.

That's all most people need. **More options** has fields for the username,
port, a key file instead of a password, and a name for the server.
You only need them if you were given those details separately.

### 4. Switch it on

Turn on **System proxy** at the top of the window. Your browser and most
other apps now go through the server. Devices on your own network, like
your router's page, a printer or a NAS, are still reached directly.

To check, click **Test**. You should see two ✓ lines: one saying sshproxy
works and one saying your computer's traffic goes through it.

### What System proxy covers, and what it doesn't

**System proxy** changes your computer's proxy setting. Only apps that
read that setting go through sshproxy, and only their traffic follows
your routing rules.

- **Covered:** Chrome, Edge, Safari, and most apps with a window.
- **Not covered: commands in a terminal** (`curl`, `git`, `pip`, `npm`,
  `brew`, …). They ignore the system setting, so they connect directly
  even when System proxy is on. See below.
- **Not covered: apps with their own proxy setting**, for example Firefox
  (unless it's set to "Use system proxy settings"), some chat apps and
  games. Click **Copy** next to **Proxy address** and paste it into the
  app's proxy setting.

**Terminal commands.** Tell them about the proxy in each terminal window
before running them. While System proxy is on, the window has a
**Copy terminal command** button that copies the right line for your
system. It looks like this:

```sh
# macOS / Linux
export http_proxy=http://127.0.0.1:7890 https_proxy=http://127.0.0.1:7890
```
```powershell
# Windows PowerShell
$env:HTTP_PROXY="http://127.0.0.1:7890"; $env:HTTPS_PROXY="http://127.0.0.1:7890"
```

To do this in every new terminal automatically, add the `export` line to
`~/.zshrc` (macOS) or `~/.bashrc` (Linux). Keep in mind those commands
then fail while sshproxy isn't running. To skip the proxy for a single
command, run it as `env -u http_proxy -u https_proxy <command>`.

### Everyday use

- **Closing the window** doesn't stop sshproxy; it keeps running in the
  menu bar or tray. To stop it, click the icon → **Quit sshproxy**. That
  also switches the system proxy off. Next time you open sshproxy, it
  switches it back on.
- **Start at login** (in the window or the icon menu) starts sshproxy
  automatically whenever you log in to your computer.
- If the network drops, sshproxy reconnects by itself. It doesn't ask for
  the password again.

### If something doesn't work

- **"Couldn't switch on the system proxy"** (this can happen on some Linux
  desktops): the window shows a **Server** and a **Port**, and where to
  enter them in your system settings. You can also click
  **Set up by hand** at any time to see them.
- **Test says your traffic doesn't go through sshproxy**: switch on
  **System proxy**, or use **Set up by hand**.
- **A routing rule seems to do nothing**: the app probably doesn't go
  through sshproxy at all. Terminal commands and apps with their own proxy
  setting need it set up separately, see
  [What System proxy covers](#what-system-proxy-covers-and-what-it-doesnt).
- **Something else**: open **Activity** at the bottom of the window. It
  shows what sshproxy is doing and any errors.

### More than one server (optional)

Add each server with **Add server**. By default sshproxy uses whichever
one is fastest right now.

- **Servers**: click a server to always use it while it works.
- **Backup chains**: a list of servers tried in order. If the first one
  stops working, sshproxy moves to the next one automatically.
- **Routing**: send some websites through a particular server or chain, or
  straight out without any proxy. Rules are checked from the top and the
  first one that matches decides.

## Command line

### Install

Download the file for your system from the
[releases page](https://github.com/zzn01/sshproxy/releases)
(`sshproxy-cli-<os>-<arch>`, e.g. `sshproxy-cli-darwin-arm64` for an
Apple-chip Mac), rename it to `sshproxy` and put it in a folder on your
`PATH`.

The files aren't code-signed, so the first run shows a warning:

- **macOS**: run `xattr -d com.apple.quarantine sshproxy` once.
- **Windows**: click **More info → Run anyway**.

### Quick start

```
$ sshproxy root@1.2.3.4
Connecting to root@1.2.3.4:22...
Password for root@1.2.3.4: ******
New server 1.2.3.4, trusted key SHA256:...
Connected to 1.2.3.4
  Proxy:  http://127.0.0.1:7890  (HTTP, HTTPS and SOCKS5 on the same port)
  Shell:  export http_proxy=http://127.0.0.1:7890 https_proxy=http://127.0.0.1:7890
  Rules:  none, everything goes through 1.2.3.4
  Reconnects automatically. Press Ctrl+C to quit.
```

Point your browser or tools at `http://127.0.0.1:7890`, or paste the
`export` line into your terminal. Tools that want a SOCKS5 proxy can use
the same port: `socks5h://127.0.0.1:7890` (the `h` resolves names on the
server).

### Options

```
sshproxy [flags] [user@]host[:port]

  -l addr   local listen address (default 127.0.0.1:7890, next free port if busy)
  -i file   private key file
  -J jump   jump host, [user@]host[:port]
  -rules f  routing rules file (default: everything goes through SSH)
  -c file   config file for several servers (see below)
  -gui      serve the desktop app's control panel in the browser
```

### Logging in

Logging in works the way `ssh` does: ssh-agent, `~/.ssh/id_ed25519`,
`id_ecdsa`, `id_rsa`, then password. Anything you type is kept in memory,
so reconnecting after a network drop never asks again.

Hosts in `~/.ssh/config` work too (`sshproxy myserver`): `HostName`, `User`,
`Port`, `IdentityFile`, single-hop `ProxyJump` and `ProxyCommand` (with
`%h`, `%p`, `%r`, `%n` tokens) are honored.

The first time you connect to a server its key is saved to
`~/.ssh/known_hosts`. If the key changes later, sshproxy refuses to connect.

### Several servers and failover

Put servers in a config file and run `sshproxy` with no argument. The
default location is `~/.config/sshproxy/config.yaml`
(`%AppData%\sshproxy\config.yaml` on Windows); `-c file` picks another.
The desktop app reads and writes the same file.

```yaml
proxies:                     # SSH servers
  hk:     root@1.2.3.4       # SSH login (or an alias from ~/.ssh/config)
  jp:     me@jp.example.com
  office: { ssh: me@office.example.com, identity: ~/.ssh/work, jump: bastion }

groups:                      # optional: backup chains
  main: [hk, jp]             # use hk; if it fails, jp
  # auto: { type: fastest, members: [hk, office] }   # lowest latency wins

rules:                       # first match wins, unmatched go direct
  - office  corp.example.com
  - office  10.0.0.0/8
  - main    *
```

- Without rules, everything goes through `fastest`: a built-in group of
  all servers that uses the one with the lowest latency.
- `pins: { main: jp }` makes a group use that member while it works.
- A `fallback` group (the short `[a, b]` form) uses the first member that
  works; `fastest` uses the one with the lowest latency and only switches
  when another is clearly faster.
- When a member breaks, new connections move to the next one immediately,
  and come back when it recovers. Switches are logged (`main -> hk`).
- A server that is unreachable at startup doesn't block the others; it keeps
  retrying in the background.
- Mistakes in the config (unknown names, typos, groups that contain each
  other) stop sshproxy at startup with the line number.

### Routing rules

With a single server on the command line, everything goes through it.
To send only some traffic through it, write a rules file and pass it with
`-rules` (in a config file, put the same lines under `rules:`). One rule
per line, the first matching rule wins, and anything unmatched connects
directly from your machine:

```
# action  pattern
ssh     corp.example.com     # this domain and all subdomains
ssh     10.0.0.0/8           # IP range
direct  192.168.1.10         # a single IP
ssh     *                    # everything else (optional catch-all)
```

Each rule names a server or group (`ssh` is the server given on the command
line). Matching stays fast with large rule lists (100k rules: ~0.1µs).

Addresses on this machine or the local network (`localhost`, `*.local`,
`127.x`, `10.x`, `172.16-31.x`, `192.168.x`, `fe80::`, `fc00::/7`) always
connect directly: the server can't reach them. `*` and the default skip
them; a rule that names them explicitly, like `office 10.0.0.0/8`, still
applies.

IP and range rules only match when the program connects to an IP address
directly. Domain names are never looked up locally just to check a rule, so
use domain rules for domain names.

## Build

```
make build     # ./sshproxy
make test
make desktop   # ./sshproxy-desktop (desktop app for this machine)
make release   # dist/sshproxy-cli-<os>-<arch> and the desktop apps in dist/desktop/
```

To publish a release, push a version tag; GitHub Actions tests, builds
and uploads everything to the releases page:

```
git tag v0.2.0 && git push origin v0.2.0
```
