package policy

import (
	"errors"
	"net/netip"
	"testing"
)

func TestClientAllowed(t *testing.T) {
	p, err := New([]string{"10.0.0.0/8", "203.0.113.7", "2001:db8::/32"}, []string{"*"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"10.1.2.3":        true,
		"::ffff:10.1.2.3": true,
		"203.0.113.7":     true,
		"203.0.113.8":     false,
		"192.168.1.1":     false,
		"2001:db8::1":     true,
		"2001:db9::1":     false,
	}
	for ip, want := range cases {
		if got := p.ClientAllowed(netip.MustParseAddr(ip)); got != want {
			t.Errorf("ClientAllowed(%s) = %v, want %v", ip, got, want)
		}
	}
}

func TestNoNetworksAllowsNobody(t *testing.T) {
	p, _ := New(nil, []string{"*"}, nil)
	if p.ClientAllowed(netip.MustParseAddr("10.0.0.1")) {
		t.Fatal("empty allowed_networks must reject all clients")
	}
}

func TestCheckSender(t *testing.T) {
	p, err := New(nil, []string{"@contoso.com", "alerts@fabrikam.com"}, []string{"CEO@contoso.com"})
	if err != nil {
		t.Fatal(err)
	}
	scanner, _ := NewMatcher([]string{"scanner@contoso.com"})

	cases := []struct {
		addr string
		user *Matcher
		ok   bool
	}{
		{"scanner@contoso.com", nil, true},
		{"Scanner@Contoso.com", nil, true},
		{"alerts@fabrikam.com", nil, true},
		{"other@fabrikam.com", nil, false},
		{"ceo@contoso.com", nil, false},
		{"", nil, false},
		{"scanner@contoso.com", scanner, true},
		{"printer@contoso.com", scanner, false},
	}
	for _, c := range cases {
		err := p.CheckSender(c.addr, c.user)
		if (err == nil) != c.ok {
			t.Errorf("CheckSender(%q) err = %v, want ok=%v", c.addr, err, c.ok)
		}
		if err != nil && !errors.Is(err, ErrSenderRejected) {
			t.Errorf("CheckSender(%q) err does not wrap ErrSenderRejected", c.addr)
		}
	}
}

func TestInvalidPattern(t *testing.T) {
	for _, p := range []string{"contoso.com", "a@b@c", "user@"} {
		if _, err := NewMatcher([]string{p}); err == nil {
			t.Errorf("NewMatcher(%q) expected error", p)
		}
	}
}
