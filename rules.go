package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"slices"
	"strings"
)

// rule sends matching destinations to the outbound named out. Exactly one
// of domain, prefix or any is set.
type rule struct {
	out    string
	domain string
	prefix netip.Prefix
	any    bool
}

// match is the reference (linear) semantics that ruleSet indexes.
func (r rule) match(host string) bool {
	if r.any {
		return !localHost(host)
	}
	if r.domain != "" {
		return host == r.domain || strings.HasSuffix(host, "."+r.domain)
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && r.prefix.Contains(ip.Unmap())
}

// parseRule parses "<outbound> <pattern>". ok is false for blank lines.
func parseRule(line string, outbounds []string) (ru rule, ok bool, err error) {
	line, _, _ = strings.Cut(line, "#")
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return rule{}, false, nil
	}
	if len(fields) != 2 {
		return rule{}, false, fmt.Errorf("want \"<outbound> <pattern>\", got %q", strings.TrimSpace(line))
	}
	ru = rule{out: strings.ToLower(fields[0])}
	if !slices.Contains(outbounds, ru.out) {
		return rule{}, false, fmt.Errorf("unknown outbound %q, want one of: %s", fields[0], strings.Join(outbounds, ", "))
	}
	// "*.example.com" means the same as "example.com".
	pat := strings.TrimPrefix(strings.ToLower(fields[1]), "*.")
	if pfx, err := netip.ParsePrefix(pat); err == nil {
		ru.prefix = pfx.Masked()
	} else if ip, err := netip.ParseAddr(pat); err == nil {
		ru.prefix = netip.PrefixFrom(ip.Unmap(), ip.Unmap().BitLen())
	} else if pat == "*" {
		ru.any = true
	} else if strings.ContainsAny(pat, "/*:") {
		return rule{}, false, fmt.Errorf("invalid pattern %q", fields[1])
	} else {
		ru.domain = strings.Trim(pat, ".")
	}
	return ru, true, nil
}

// parseRules reads a rules file. name is used in errors; outbounds lists
// the valid outbound names.
func parseRules(r io.Reader, name string, outbounds []string) (*ruleSet, error) {
	var rs []rule
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		ru, ok, err := parseRule(sc.Text(), outbounds)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", name, n, err)
		}
		if ok {
			rs = append(rs, ru)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return newRuleSet(rs), nil
}

const noMatch = math.MaxInt

// ruleSet answers "first matching rule" without scanning every rule:
// domains are looked up by suffix in a map, IPs walk a prefix trie, and
// the lowest rule index among all matches wins.
type ruleSet struct {
	rules   []rule
	domains map[string]int
	v4, v6  *trieNode
	any     int
}

type trieNode struct {
	child [2]*trieNode
	idx   int
}

func newRuleSet(rs []rule) *ruleSet {
	s := &ruleSet{
		rules:   rs,
		domains: map[string]int{},
		v4:      &trieNode{idx: noMatch},
		v6:      &trieNode{idx: noMatch},
		any:     noMatch,
	}
	for i, r := range rs {
		switch {
		case r.any:
			s.any = min(s.any, i)
		case r.domain != "":
			if _, ok := s.domains[r.domain]; !ok {
				s.domains[r.domain] = i
			}
		default:
			s.insert(r.prefix, i)
		}
	}
	return s
}

func (s *ruleSet) insert(p netip.Prefix, idx int) {
	n := s.v6
	if p.Addr().Is4() {
		n = s.v4
	}
	b := p.Addr().AsSlice()
	for i := range p.Bits() {
		bit := b[i/8] >> (7 - i%8) & 1
		if n.child[bit] == nil {
			n.child[bit] = &trieNode{idx: noMatch}
		}
		n = n.child[bit]
	}
	n.idx = min(n.idx, idx)
}

func (s *ruleSet) lookupIP(ip netip.Addr) int {
	n := s.v6
	if ip.Is4() {
		n = s.v4
	}
	best := n.idx
	b := ip.AsSlice()
	for i := 0; i < len(b)*8 && n != nil; i++ {
		n = n.child[b[i/8]>>(7-i%8)&1]
		if n != nil {
			best = min(best, n.idx)
		}
	}
	return best
}

// len returns the number of rules.
func (s *ruleSet) len() int { return len(s.rules) }

// route returns the outbound name for host. Unmatched hosts go direct.
func (s *ruleSet) route(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	best := s.any
	if localHost(host) {
		best = noMatch
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		best = min(best, s.lookupIP(ip.Unmap()))
	} else {
		for h := host; ; {
			if i, ok := s.domains[h]; ok {
				best = min(best, i)
			}
			dot := strings.IndexByte(h, '.')
			if dot < 0 {
				break
			}
			h = h[dot+1:]
		}
	}
	if best == noMatch {
		return outDirect
	}
	return s.rules[best].out
}

// localHost reports whether host is this machine or on its local network,
// which a remote server can't reach. The catch-all rule "*" and the
// default outbound skip such hosts; rules naming them still apply.
func localHost(host string) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return host == "localhost" || strings.HasSuffix(host, ".local")
}

// dialFunc opens a TCP connection to addr ("host:port").
type dialFunc func(ctx context.Context, addr string) (net.Conn, error)

// router picks an outbound per connection. With no rules everything except
// local hosts goes to the default outbound.
type router struct {
	rules     *ruleSet
	outbounds map[string]outbound
	def       string // outbound used when there are no rules
	logf      func(string, ...any)
}

func (r *router) dial(ctx context.Context, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	route := r.def
	if r.rules != nil {
		route = r.rules.route(host)
	} else if localHost(host) {
		route = outDirect
	}
	conn, err := r.outbounds[route].Dial(ctx, addr)
	if err != nil {
		err = fmt.Errorf("connect to %s (%s): %w", addr, route, explainedError{err})
		r.logf("%v", err)
	}
	return conn, err
}

// explainedError prints as explain(err) but keeps err for errors.As.
type explainedError struct{ err error }

func (e explainedError) Error() string { return explain(e.err) }
func (e explainedError) Unwrap() error { return e.err }
