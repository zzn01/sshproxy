package main

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"
)

// healthConfig controls active health checks.
type healthConfig struct {
	url          string
	interval     time.Duration // between checks while healthy
	downInterval time.Duration // between checks while unhealthy
	timeout      time.Duration
}

var defaultHealth = healthConfig{
	url:          "http://www.gstatic.com/generate_204",
	interval:     60 * time.Second,
	downInterval: 10 * time.Second,
	timeout:      5 * time.Second,
}

// connector is implemented by outbounds that know their own connection
// state (SSH). Their health is that state; probes only measure latency,
// so a server without internet access (e.g. an intranet jump box) is not
// reported as down.
type connector interface {
	connected() bool
}

// leaf wraps one upstream with health tracking so it can join groups.
type leaf struct {
	name     string
	out      outbound
	logf     func(string, ...any)
	onChange func() // called when health flips

	mu   sync.Mutex
	down bool
	lat  time.Duration
	wake chan struct{}
}

func newLeaf(name string, out outbound, logf func(string, ...any)) *leaf {
	return &leaf{name: name, out: out, logf: logf, onChange: func() {}, wake: make(chan struct{}, 1)}
}

func (l *leaf) healthy() bool {
	if c, ok := l.out.(connector); ok {
		return c.connected()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return !l.down
}

func (l *leaf) setOnChange(f func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.onChange = f
}

// notify tells the owner that health or latency changed.
func (l *leaf) notify() {
	l.mu.Lock()
	f := l.onChange
	l.mu.Unlock()
	f()
}

func (l *leaf) latency() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lat
}

// Dial marks the leaf down right away when its upstream is broken, so
// groups move on without waiting for the next check.
func (l *leaf) Dial(ctx context.Context, addr string) (net.Conn, error) {
	conn, err := l.out.Dial(ctx, addr)
	if err != nil && isUpstreamFailure(err) && ctx.Err() == nil {
		if _, ok := l.out.(connector); !ok {
			l.setDown(true, 0)
		}
		l.poke()
	}
	return conn, err
}

func (l *leaf) Close() error { return l.out.Close() }

func (l *leaf) poke() {
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

func (l *leaf) setDown(down bool, lat time.Duration) {
	l.mu.Lock()
	changed := l.down != down
	l.down, l.lat = down, lat
	l.mu.Unlock()
	if !changed {
		return
	}
	if down {
		l.logf("%s is down", l.name)
	} else {
		l.logf("%s is back", l.name)
	}
	l.notify()
}

func (l *leaf) setLatency(lat time.Duration) {
	l.mu.Lock()
	l.lat = lat
	l.mu.Unlock()
}

// monitor probes the leaf until ctx is done.
func (l *leaf) monitor(ctx context.Context, hc healthConfig) {
	conn, isConnector := l.out.(connector)
	for {
		switch {
		case isConnector && !conn.connected():
			l.setLatency(0)
		case isConnector:
			lat, err := probe(ctx, l.out, hc)
			if err != nil {
				lat = 0
			}
			l.setLatency(lat)
			l.notify()
		default:
			lat, err := probe(ctx, l.out, hc)
			l.setDown(err != nil, lat)
		}
		wait := hc.interval
		if !l.healthy() {
			wait = hc.downInterval
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		case <-l.wake:
		}
	}
}

// probe fetches hc.url through out and returns the time to the response
// headers.
func probe(ctx context.Context, out outbound, hc healthConfig) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, hc.timeout)
	defer cancel()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return out.Dial(ctx, addr)
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, hc.url, nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return time.Since(start), nil
}
