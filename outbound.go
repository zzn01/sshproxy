package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"slices"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Built-in outbound names.
const (
	outSSH    = "ssh" // the SSH server given on the command line
	outDirect = "direct"
	// outFastest is a built-in group of every proxy, lowest latency first.
	outFastest = "fastest"
)

// outbound opens connections to destinations on behalf of the proxy.
type outbound interface {
	Dial(ctx context.Context, addr string) (net.Conn, error)
	Close() error
}

// directOutbound connects from the local machine.
type directOutbound struct{ net.Dialer }

func (d *directOutbound) Dial(ctx context.Context, addr string) (net.Conn, error) {
	return d.DialContext(ctx, "tcp", addr)
}

func (d *directOutbound) Close() error { return nil }

// isUpstreamFailure reports whether a Dial error means the upstream itself
// is broken, as opposed to the upstream being fine but the target refusing
// or not existing. Only upstream failures justify trying another member.
func isUpstreamFailure(err error) bool {
	var oce *ssh.OpenChannelError
	return !errors.As(err, &oce) && !errors.Is(err, context.Canceled)
}

// member is an outbound that can be part of a group.
type member interface {
	outbound
	healthy() bool
	latency() time.Duration // 0 means unknown
}

// Group policies.
const (
	policyFallback = "fallback"
	policyFastest  = "fastest"
)

// stickiness is how much faster another member must be before a fastest
// group leaves its current, healthy member.
const stickiness = 50 * time.Millisecond

// group picks one of its members per connection and fails over to the
// next one when a member's upstream is broken.
type group struct {
	name   string
	policy string
	logf   func(string, ...any)

	mu      sync.Mutex
	names   []string
	members []member
	current member // chosen member, nil before the first choice
	pinned  string // member the user picked; used while it is healthy
}

func newGroup(name, policy string, names []string, members []member, logf func(string, ...any)) *group {
	return &group{name: name, policy: policy, names: names, members: members, logf: logf}
}

// snapshot returns the members and the name of the current choice.
func (g *group) snapshot() (names []string, members []member, current string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if i := slices.Index(g.members, g.current); i >= 0 {
		current = g.names[i]
	}
	return g.names, g.members, current
}

// setPinned makes the group prefer the member called name while it is
// healthy; "" goes back to automatic choice.
func (g *group) setPinned(name string) {
	g.mu.Lock()
	g.pinned = name
	g.mu.Unlock()
	g.order() // log the switch now
}

func (g *group) pin() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.pinned
}

// size returns the number of members.
func (g *group) size() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.members)
}

// order returns members in the order they should be tried, and records
// (and logs) a change of the preferred member.
func (g *group) order() []member {
	g.mu.Lock()
	names, members, current, pinned := g.names, g.members, g.current, g.pinned
	g.mu.Unlock()
	if len(members) == 0 {
		return nil
	}
	var up, down []int
	for i, m := range members {
		if m.healthy() {
			up = append(up, i)
		} else {
			down = append(down, i)
		}
	}
	if g.policy == policyFastest && len(up) > 0 {
		lat := func(i int) time.Duration {
			if l := members[i].latency(); l > 0 {
				return l
			}
			return math.MaxInt64 // unknown latency sorts last
		}
		slices.SortStableFunc(up, func(a, b int) int { return cmp.Compare(lat(a), lat(b)) })
		cur := slices.IndexFunc(up, func(i int) bool { return members[i] == current })
		if cur > 0 && lat(up[cur])-lat(up[0]) <= stickiness {
			sticky := up[cur]
			up = append([]int{sticky}, slices.Delete(up, cur, cur+1)...)
		}
	}
	if p := slices.Index(names, pinned); p >= 0 {
		if at := slices.Index(up, p); at > 0 {
			up = append([]int{p}, slices.Delete(up, at, at+1)...)
		}
	}
	idx := append(up, down...)
	order := make([]member, len(idx))
	for i, j := range idx {
		order[i] = members[j]
	}

	g.mu.Lock()
	if g.current != order[0] && slices.Equal(g.members, members) {
		msg := fmt.Sprintf("%s -> %s", g.name, names[idx[0]])
		if l := order[0].latency(); l > 0 {
			msg += fmt.Sprintf(" (%dms)", l.Milliseconds())
		}
		g.logf("%s", msg)
		g.current = order[0]
	}
	g.mu.Unlock()
	return order
}

func (g *group) Dial(ctx context.Context, addr string) (net.Conn, error) {
	lastErr := fmt.Errorf("group %s has no members", g.name)
	for _, m := range g.order() {
		conn, err := m.Dial(ctx, addr)
		if err == nil {
			return conn, nil
		}
		if !isUpstreamFailure(err) || ctx.Err() != nil {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

// Close does nothing: members are closed by their owner.
func (g *group) Close() error { return nil }

func (g *group) healthy() bool {
	g.mu.Lock()
	members := g.members
	g.mu.Unlock()
	return slices.ContainsFunc(members, member.healthy)
}

func (g *group) latency() time.Duration {
	if order := g.order(); len(order) > 0 {
		return order[0].latency()
	}
	return 0
}
