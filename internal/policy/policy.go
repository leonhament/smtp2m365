// Package policy decides which clients may connect and which sender
// addresses they may use.
package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

var ErrSenderRejected = errors.New("sender rejected by policy")

type Policy struct {
	networks []netip.Prefix
	allowed  *Matcher
	denied   *Matcher
}

func New(networks, allowed, denied []string) (*Policy, error) {
	p := &Policy{}
	for _, n := range networks {
		prefix, err := parsePrefix(n)
		if err != nil {
			return nil, fmt.Errorf("allowed_networks: %w", err)
		}
		p.networks = append(p.networks, prefix)
	}
	var err error
	if p.allowed, err = NewMatcher(allowed); err != nil {
		return nil, fmt.Errorf("allowed_senders: %w", err)
	}
	if p.denied, err = NewMatcher(denied); err != nil {
		return nil, fmt.Errorf("denied_senders: %w", err)
	}
	return p, nil
}

// parsePrefix accepts a CIDR or a bare IP address.
func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func (p *Policy) ClientAllowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, n := range p.networks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// CheckSender reports whether addr may be used as a sender. The deny list
// wins over every allow list. userAllowed, when non-nil, is an additional
// per-user restriction on top of the global allow list.
func (p *Policy) CheckSender(addr string, userAllowed *Matcher) error {
	addr = Normalize(addr)
	switch {
	case addr == "":
		return fmt.Errorf("%w: empty sender", ErrSenderRejected)
	case p.denied.Match(addr):
		return fmt.Errorf("%w: %s is denied", ErrSenderRejected, addr)
	case !p.allowed.Match(addr):
		return fmt.Errorf("%w: %s is not an allowed sender", ErrSenderRejected, addr)
	case userAllowed != nil && !userAllowed.Match(addr):
		return fmt.Errorf("%w: %s is not allowed for this user", ErrSenderRejected, addr)
	}
	return nil
}

func Normalize(addr string) string {
	return strings.ToLower(strings.TrimSpace(addr))
}

// Matcher matches addresses against a list of patterns: an exact address,
// "@domain" (or "*@domain") for a whole domain, or "*" for everything.
// A Matcher built from an empty list matches nothing.
type Matcher struct {
	any     bool
	addrs   map[string]bool
	domains map[string]bool
}

func NewMatcher(patterns []string) (*Matcher, error) {
	m := &Matcher{addrs: map[string]bool{}, domains: map[string]bool{}}
	for _, raw := range patterns {
		p := Normalize(raw)
		switch {
		case p == "*":
			m.any = true
		case strings.HasPrefix(p, "@") || strings.HasPrefix(p, "*@"):
			m.domains[p[strings.Index(p, "@")+1:]] = true
		case strings.Count(p, "@") == 1 && !strings.HasPrefix(p, "@") && !strings.HasSuffix(p, "@"):
			m.addrs[p] = true
		default:
			return nil, fmt.Errorf("invalid sender pattern %q", raw)
		}
	}
	return m, nil
}

func (m *Matcher) Match(addr string) bool {
	addr = Normalize(addr)
	if m.any || m.addrs[addr] {
		return true
	}
	at := strings.LastIndex(addr, "@")
	return at >= 0 && m.domains[addr[at+1:]]
}
