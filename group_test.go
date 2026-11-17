package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// fakeMember is a group member with scripted health and dial results.
type fakeMember struct {
	up      bool
	lat     time.Duration
	dialErr error
	dialed  int
}

func (f *fakeMember) Dial(context.Context, string) (net.Conn, error) {
	f.dialed++
	if f.dialErr != nil {
		return nil, f.dialErr
	}
	c, _ := net.Pipe()
	return c, nil
}

func (f *fakeMember) Close() error           { return nil }
func (f *fakeMember) healthy() bool          { return f.up }
func (f *fakeMember) latency() time.Duration { return f.lat }

type logRecorder struct{ lines []string }

func (r *logRecorder) logf(format string, args ...any) {
	r.lines = append(r.lines, fmt.Sprintf(format, args...))
}

func testGroup(policy string, ms ...*fakeMember) (*group, *logRecorder) {
	names := make([]string, len(ms))
	members := make([]member, len(ms))
	for i, m := range ms {
		names[i] = string(rune('a' + i))
		members[i] = m
	}
	rec := &logRecorder{}
	return newGroup("g", policy, names, members, rec.logf), rec
}

func dialOnce(t *testing.T, g *group) error {
	t.Helper()
	c, err := g.Dial(context.Background(), "x:1")
	if c != nil {
		c.Close()
	}
	return err
}

func TestFallbackSkipsUnhealthy(t *testing.T) {
	a, b, c := &fakeMember{}, &fakeMember{up: true}, &fakeMember{up: true}
	g, _ := testGroup(policyFallback, a, b, c)
	dialOnce(t, g)
	if a.dialed != 0 || b.dialed != 1 || c.dialed != 0 {
		t.Fatalf("dialed a=%d b=%d c=%d", a.dialed, b.dialed, c.dialed)
	}
}

func TestDialTimeFailover(t *testing.T) {
	a := &fakeMember{up: true, dialErr: errors.New("upstream gone")}
	b := &fakeMember{up: true}
	g, _ := testGroup(policyFallback, a, b)
	if err := dialOnce(t, g); err != nil {
		t.Fatal(err)
	}
	if a.dialed != 1 || b.dialed != 1 {
		t.Fatalf("dialed a=%d b=%d", a.dialed, b.dialed)
	}
}

func TestTargetFailureIsNotFailedOver(t *testing.T) {
	a := &fakeMember{up: true, dialErr: &ssh.OpenChannelError{Reason: ssh.ConnectionFailed}}
	b := &fakeMember{up: true}
	g, _ := testGroup(policyFallback, a, b)
	if err := dialOnce(t, g); err == nil || b.dialed != 0 {
		t.Fatalf("err=%v b.dialed=%d, want the target error and no failover", err, b.dialed)
	}
}

func TestAllDownStillTries(t *testing.T) {
	a, b := &fakeMember{dialErr: errors.New("down")}, &fakeMember{}
	g, _ := testGroup(policyFallback, a, b)
	if err := dialOnce(t, g); err != nil || a.dialed != 1 || b.dialed != 1 {
		t.Fatalf("err=%v a=%d b=%d", err, a.dialed, b.dialed)
	}
}

func TestFastestWithStickiness(t *testing.T) {
	a := &fakeMember{up: true, lat: 100 * time.Millisecond}
	b := &fakeMember{up: true, lat: 30 * time.Millisecond}
	c := &fakeMember{up: true} // unknown latency sorts last
	g, rec := testGroup(policyFastest, a, b, c)
	if first := g.order()[0]; first != b {
		t.Fatalf("picked %v, want b", first)
	}
	a.lat = 10 * time.Millisecond // faster, but within the tolerance
	if first := g.order()[0]; first != b {
		t.Fatalf("switched to %v too eagerly", first)
	}
	a.lat = 5 * time.Millisecond
	b.lat = 80 * time.Millisecond
	if first := g.order()[0]; first != a {
		t.Fatalf("picked %v, want a", first)
	}
	b.up = false
	a.up = false
	if first := g.order()[0]; first != c {
		t.Fatalf("picked %v, want c", first)
	}
	if want := []string{"g -> b (30ms)", "g -> a (5ms)", "g -> c"}; !slices.Equal(rec.lines, want) {
		t.Fatalf("logs %q, want %q", rec.lines, want)
	}
}

func TestNestedGroup(t *testing.T) {
	x, y := &fakeMember{}, &fakeMember{up: true}
	inner := newGroup("inner", policyFallback, []string{"x"}, []member{x}, t.Logf)
	outer := newGroup("outer", policyFallback, []string{"inner", "y"}, []member{inner, y}, t.Logf)
	if _, err := outer.Dial(context.Background(), "x:1"); err != nil || y.dialed != 1 || x.dialed != 0 {
		t.Fatalf("err=%v x=%d y=%d", err, x.dialed, y.dialed)
	}
	x.up = true
	outer.Dial(context.Background(), "x:1")
	if x.dialed != 1 {
		t.Fatal("outer did not return to inner once it recovered")
	}
}

func TestLeafMarksDownOnUpstreamFailure(t *testing.T) {
	f := &fakeMember{up: true, dialErr: errors.New("connection refused")}
	rec := &logRecorder{}
	l := newLeaf("hk", f, rec.logf)
	l.Dial(context.Background(), "x:1")
	if l.healthy() || !slices.Equal(rec.lines, []string{"hk is down"}) {
		t.Fatalf("healthy=%v logs=%q", l.healthy(), rec.lines)
	}
}

func TestPinnedMember(t *testing.T) {
	a := &fakeMember{up: true, lat: 10 * time.Millisecond}
	b := &fakeMember{up: true, lat: 90 * time.Millisecond}
	g, _ := testGroup(policyFastest, a, b)
	g.setPinned("b")
	if first := g.order()[0]; first != b {
		t.Fatalf("picked %v, want the pinned b", first)
	}
	b.up = false // a pinned member that fails gives way to automatic choice
	if first := g.order()[0]; first != a {
		t.Fatalf("picked %v, want a", first)
	}
	b.up = true
	g.setPinned("")
	if first := g.order()[0]; first != a {
		t.Fatalf("picked %v after unpinning, want the fastest a", first)
	}
}
