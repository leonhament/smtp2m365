package tlsconf

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// checkDelegation verifies that _acme-challenge.<hostname> is a CNAME
// (possibly through a chain) to alias. Doing this before contacting
// Let's Encrypt turns a missing record into a clear error instead of
// failed validations, which count against Let's Encrypt rate limits.
func checkDelegation(ctx context.Context, hostname, alias string, lookup func(context.Context, string) (string, error)) error {
	source := "_acme-challenge." + fqdn(hostname)
	want := fqdn(alias)

	name := source
	for range 8 {
		target, err := lookup(ctx, name)
		if err != nil {
			return fmt.Errorf("look up CNAME %s: %w", name, err)
		}
		if target == "" {
			break
		}
		name = fqdn(target)
		if name == want {
			return nil
		}
	}
	found := "no CNAME"
	if name != source {
		found = "it points to " + strings.TrimSuffix(name, ".")
	}
	return fmt.Errorf("ACME challenge delegation is not set up (%s). Create this record at the DNS provider of %s:\n  %s  CNAME  %s",
		found, hostname, strings.TrimSuffix(source, "."), strings.TrimSuffix(want, "."))
}

// lookupCNAME returns the CNAME target of name, or "" when name has no
// CNAME. net.LookupCNAME cannot tell those cases apart reliably, so the
// query is made directly.
func lookupCNAME(ctx context.Context, name string) (string, error) {
	servers := []string{"1.1.1.1:53", "8.8.8.8:53"}
	if cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cfg.Servers) > 0 {
		servers = servers[:0]
		for _, s := range cfg.Servers {
			servers = append(servers, net.JoinHostPort(s, cfg.Port))
		}
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeCNAME)
	client := &dns.Client{Timeout: 5 * time.Second}
	var lastErr error
	for _, server := range servers {
		resp, _, err := client.ExchangeContext(ctx, msg, server)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
			lastErr = fmt.Errorf("%s answered %s", server, dns.RcodeToString[resp.Rcode])
			continue
		}
		for _, rr := range resp.Answer {
			if c, ok := rr.(*dns.CNAME); ok && strings.EqualFold(c.Hdr.Name, dns.Fqdn(name)) {
				return c.Target, nil
			}
		}
		return "", nil
	}
	return "", lastErr
}

func fqdn(name string) string {
	return strings.ToLower(dns.Fqdn(strings.TrimSpace(name)))
}
