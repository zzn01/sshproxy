package main

import (
	"bufio"
	"crypto/ed25519"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

// promptFunc asks the user for a line of input; echo controls whether the
// typed text is shown.
type promptFunc func(prompt string, echo bool) (string, error)

// authenticator builds SSH client configs. It caches every secret the user
// types and every decrypted key, so reconnects never prompt unless a cached
// secret is rejected.
type authenticator struct {
	prompt     promptFunc
	knownHosts string // path to known_hosts
	useAgent   bool

	mu      sync.Mutex
	secrets map[string]string
	keys    map[string]ssh.Signer // decrypted keys by path
}

func newAuthenticator(prompt promptFunc, knownHosts string) *authenticator {
	return &authenticator{
		prompt:     prompt,
		knownHosts: knownHosts,
		useAgent:   true,
		secrets:    map[string]string{},
		keys:       map[string]ssh.Signer{},
	}
}

// termMu keeps prompts and messages printed during handshakes from
// interleaving when several servers connect at once.
var termMu sync.Mutex

// notify prints a line to the terminal without breaking a pending prompt.
func notify(format string, args ...any) {
	termMu.Lock()
	defer termMu.Unlock()
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// terminalPrompt reads from the controlling terminal.
func terminalPrompt() promptFunc {
	stdin := bufio.NewReader(os.Stdin)
	return func(prompt string, echo bool) (string, error) {
		termMu.Lock()
		defer termMu.Unlock()
		fd := int(os.Stdin.Fd())
		if !term.IsTerminal(fd) {
			return "", errNoTerminal
		}
		fmt.Fprint(os.Stderr, prompt)
		if echo {
			line, err := stdin.ReadString('\n')
			return trimNewline(line), err
		}
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
}

var errNoTerminal = errors.New("no terminal to ask for a password; use an SSH key or ssh-agent")

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

// secret returns the cached value for key, or prompts when there is none or
// fresh is set (the cached value was just rejected).
func (a *authenticator) secret(key, prompt string, fresh, echo bool) (string, error) {
	a.mu.Lock()
	v, ok := a.secrets[key]
	a.mu.Unlock()
	if ok && !fresh {
		return v, nil
	}
	v, err := a.prompt(prompt, echo)
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	a.secrets[key] = v
	a.mu.Unlock()
	return v, nil
}

// clientConfig returns a config for one connection attempt to d. The
// returned cleanup func must be called once the handshake is over.
func (a *authenticator) clientConfig(d *dest) (*ssh.ClientConfig, func()) {
	cleanup := func() {}
	var agentSigners func() ([]ssh.Signer, error)
	if sock := os.Getenv("SSH_AUTH_SOCK"); a.useAgent && sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			agentSigners = agent.NewClient(conn).Signers
			cleanup = func() { conn.Close() }
		}
	}

	// First round: agent + unencrypted (or already decrypted) keys.
	// Second round, only if the first failed: ask for passphrases.
	keyRound := 0
	pubkeys := ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
		keyRound++
		if keyRound > 1 {
			return a.decryptKeys(d), nil
		}
		var signers []ssh.Signer
		if agentSigners != nil {
			if s, err := agentSigners(); err == nil {
				signers = s
			}
		}
		return append(signers, a.plainKeys(d)...), nil
	})

	pwTries := 0
	password := ssh.PasswordCallback(func() (string, error) {
		pwTries++
		return a.secret("password "+d.String(), fmt.Sprintf("Password for %s: ", d.label()), pwTries > 1, false)
	})

	kiTries := map[string]int{}
	interactive := ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i, q := range questions {
			kiTries[q]++
			fresh := kiTries[q] > 1
			if instruction != "" && (fresh || !a.hasSecret("ki "+d.String()+" "+q)) {
				notify("%s", instruction)
				instruction = ""
			}
			v, err := a.secret("ki "+d.String()+" "+q, fmt.Sprintf("(%s) %s", d.label(), q), fresh, echos[i])
			if err != nil {
				return nil, err
			}
			answers[i] = v
		}
		return answers, nil
	})

	cfg := &ssh.ClientConfig{
		User: d.User,
		Auth: []ssh.AuthMethod{
			ssh.RetryableAuthMethod(pubkeys, 2),
			ssh.RetryableAuthMethod(password, 3),
			ssh.RetryableAuthMethod(interactive, 3),
		},
		HostKeyCallback:   a.hostKeyCallback,
		HostKeyAlgorithms: a.knownAlgorithms(d.addr()),
	}
	return cfg, cleanup
}

// adopt copies the secrets and decrypted keys of another authenticator,
// e.g. one that just checked a login typed into the panel.
func (a *authenticator) adopt(o *authenticator) {
	o.mu.Lock()
	secrets, keys := maps.Clone(o.secrets), maps.Clone(o.keys)
	o.mu.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()
	maps.Copy(a.secrets, secrets)
	maps.Copy(a.keys, keys)
}

func (a *authenticator) hasSecret(key string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.secrets[key]
	return ok
}

// keyFiles lists the private keys to try for d.
func keyFiles(d *dest) []string {
	if len(d.IdentityFiles) > 0 {
		return d.IdentityFiles
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var files []string
	for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
		files = append(files, filepath.Join(home, ".ssh", name))
	}
	return files
}

// plainKeys loads keys that need no passphrase, plus keys already decrypted.
func (a *authenticator) plainKeys(d *dest) []ssh.Signer {
	var signers []ssh.Signer
	for _, path := range keyFiles(d) {
		a.mu.Lock()
		s, ok := a.keys[path]
		a.mu.Unlock()
		if ok {
			signers = append(signers, s)
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if s, err := ssh.ParsePrivateKey(data); err == nil {
			signers = append(signers, s)
		}
	}
	return signers
}

// decryptKeys prompts for passphrases of encrypted keys not yet decrypted.
func (a *authenticator) decryptKeys(d *dest) []ssh.Signer {
	var signers []ssh.Signer
	for _, path := range keyFiles(d) {
		a.mu.Lock()
		_, ok := a.keys[path]
		a.mu.Unlock()
		if ok {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if _, err := ssh.ParsePrivateKey(data); !errors.As(err, new(*ssh.PassphraseMissingError)) {
			continue
		}
		pass, err := a.secret("passphrase "+path, fmt.Sprintf("Passphrase for key %s: ", path), false, false)
		if err != nil {
			continue
		}
		s, err := ssh.ParsePrivateKeyWithPassphrase(data, []byte(pass))
		if err != nil {
			notify("Wrong passphrase for %s, skipping this key", path)
			a.mu.Lock()
			delete(a.secrets, "passphrase "+path)
			a.mu.Unlock()
			continue
		}
		a.mu.Lock()
		a.keys[path] = s
		a.mu.Unlock()
		signers = append(signers, s)
	}
	return signers
}

// hostKeyChangedError reports a known host presenting a different key.
type hostKeyChangedError struct {
	host        string
	fingerprint string
}

func (e *hostKeyChangedError) Error() string {
	return fmt.Sprintf("the identity of %s has CHANGED (new key %s).\n"+
		"Someone could be intercepting your connection, or the server was reinstalled.\n"+
		"If you are sure the change is expected, remove the old entry with:\n"+
		"  ssh-keygen -R %s",
		e.host, e.fingerprint, e.host)
}

func (a *authenticator) openKnownHosts() (ssh.HostKeyCallback, error) {
	if err := os.MkdirAll(filepath.Dir(a.knownHosts), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(a.knownHosts, os.O_CREATE|os.O_RDONLY, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	return knownhosts.New(a.knownHosts)
}

// hostKeyCallback trusts unknown hosts on first use and records them;
// changed keys are always refused.
func (a *authenticator) hostKeyCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	check, err := a.openKnownHosts()
	if err != nil {
		return fmt.Errorf("read known_hosts: %w", err)
	}
	err = check(hostname, remote, key)
	var ke *knownhosts.KeyError
	if !errors.As(err, &ke) {
		return err
	}
	fp := ssh.FingerprintSHA256(key)
	if len(ke.Want) > 0 {
		return &hostKeyChangedError{host: knownhosts.Normalize(hostname), fingerprint: fp}
	}
	f, err := os.OpenFile(a.knownHosts, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("write known_hosts: %w", err)
	}
	defer f.Close()
	if _, err := fmt.Fprintln(f, knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key)); err != nil {
		return fmt.Errorf("write known_hosts: %w", err)
	}
	notify("New server %s, trusted key %s", knownhosts.Normalize(hostname), fp)
	return nil
}

// knownAlgorithms returns host key algorithms matching keys already recorded
// for addr, so the server is not asked for a key type we have never seen
// (which knownhosts would report as a mismatch). Nil means "any".
func (a *authenticator) knownAlgorithms(addr string) []string {
	check, err := a.openKnownHosts()
	if err != nil {
		return nil
	}
	probe, err := probeKey()
	if err != nil {
		return nil
	}
	var ke *knownhosts.KeyError
	if !errors.As(check(addr, &net.TCPAddr{}, probe), &ke) {
		return nil
	}
	var algos []string
	for _, k := range ke.Want {
		if k.Key.Type() == ssh.KeyAlgoRSA {
			algos = append(algos, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA)
		} else {
			algos = append(algos, k.Key.Type())
		}
	}
	return algos
}

// probeKey is a throwaway key used only to list known keys for a host.
var probeKey = sync.OnceValues(func() (ssh.PublicKey, error) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	return ssh.NewPublicKey(pub)
})
