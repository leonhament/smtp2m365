// Package config loads and validates the smtp2m365 YAML configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// Hostname is the public DNS name of the gateway. It is used for the
	// SMTP greeting and as the name on the TLS certificate.
	Hostname  string     `yaml:"hostname"`
	Listeners []Listener `yaml:"listeners"`
	Admin     Admin      `yaml:"admin"`
	TLS       TLS        `yaml:"tls"`
	Exchange  Exchange   `yaml:"exchange"`
	Policy    Policy     `yaml:"policy"`
	Users     []User     `yaml:"users"`
	Limits    Limits     `yaml:"limits"`
	Reporting Reporting  `yaml:"reporting"`
}

type Listener struct {
	Addr string `yaml:"addr"`
	// Mode is "implicit" (TLS from the first byte, e.g. port 465) or
	// "starttls" (plaintext greeting, STARTTLS required before MAIL/AUTH).
	Mode string `yaml:"mode"`
}

const (
	ModeImplicit = "implicit"
	ModeStartTLS = "starttls"
)

type Admin struct {
	// Addr for the reporting/health HTTP endpoint. Empty disables it.
	Addr string `yaml:"addr"`
	// Token protects /api/*. /healthz is always unauthenticated.
	Token string `yaml:"token"`
}

type TLS struct {
	// Mode is "acme" (Let's Encrypt via certmagic) or "files".
	Mode     string `yaml:"mode"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	ACME     ACME   `yaml:"acme"`
}

type ACME struct {
	Email   string `yaml:"email"`
	Staging bool   `yaml:"staging"`
	// Challenge is "dns-azure" (recommended, no inbound port 80 needed) or "http-01".
	Challenge string   `yaml:"challenge"`
	Storage   string   `yaml:"storage"`
	AzureDNS  AzureDNS `yaml:"azure_dns"`
}

type AzureDNS struct {
	SubscriptionID string `yaml:"subscription_id"`
	ResourceGroup  string `yaml:"resource_group"`
}

const (
	ChallengeDNSAzure = "dns-azure"
	ChallengeHTTP01   = "http-01"
)

type Exchange struct {
	// Method is "smtp" (SMTP client submission with XOAUTH2, RBAC role
	// "Application SMTP.SendAsApp") or "graph" (Graph sendMail, RBAC role
	// "Application Mail.Send").
	Method        string        `yaml:"method"`
	SMTPHost      string        `yaml:"smtp_host"`
	GraphEndpoint string        `yaml:"graph_endpoint"`
	TokenScope    string        `yaml:"token_scope"`
	Timeout       time.Duration `yaml:"timeout"`
}

const (
	MethodSMTP  = "smtp"
	MethodGraph = "graph"
)

type Policy struct {
	// AllowedNetworks lists CIDRs that may connect. Empty means nobody.
	AllowedNetworks []string `yaml:"allowed_networks"`
	RequireAuth     bool     `yaml:"require_auth"`
	// AllowedSenders: exact addresses, "@domain" or "*".
	AllowedSenders []string `yaml:"allowed_senders"`
	DeniedSenders  []string `yaml:"denied_senders"`
	// CheckHeaderFrom applies the sender policy to the From: header too,
	// not only the envelope sender.
	CheckHeaderFrom bool `yaml:"check_header_from"`
	// MaxAuthFailures per client IP within AuthFailureWindow before the
	// IP is temporarily refused.
	MaxAuthFailures   int           `yaml:"max_auth_failures"`
	AuthFailureWindow time.Duration `yaml:"auth_failure_window"`
}

type User struct {
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"password_hash"`
	// AllowedSenders further restricts which senders this user may use.
	AllowedSenders []string `yaml:"allowed_senders"`
}

type Limits struct {
	MaxMessageBytes int64 `yaml:"max_message_bytes"`
	MaxRecipients   int   `yaml:"max_recipients"`
}

type Reporting struct {
	// RecentEvents is how many events the admin API keeps in memory.
	RecentEvents int `yaml:"recent_events"`
}

func defaults() Config {
	return Config{
		Admin: Admin{Addr: "127.0.0.1:8080"},
		TLS: TLS{
			Mode: "acme",
			ACME: ACME{Challenge: ChallengeDNSAzure, Storage: "/data/certmagic"},
		},
		Exchange: Exchange{Method: MethodSMTP, Timeout: 2 * time.Minute},
		Policy: Policy{
			RequireAuth:       true,
			CheckHeaderFrom:   true,
			MaxAuthFailures:   10,
			AuthFailureWindow: 15 * time.Minute,
		},
		Limits:    Limits{MaxMessageBytes: 35 << 20, MaxRecipients: 100},
		Reporting: Reporting{RecentEvents: 1000},
	}
}

// envRef matches ${VAR}. The bare $VAR form is deliberately not expanded
// because bcrypt hashes contain '$'.
var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw = envRef.ReplaceAllFunc(raw, func(m []byte) []byte {
		return []byte(os.Getenv(string(envRef.FindSubmatch(m)[1])))
	})

	cfg := defaults()
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(cfg.Listeners) == 0 {
		cfg.Listeners = []Listener{{Addr: ":465", Mode: ModeImplicit}, {Addr: ":587", Mode: ModeStartTLS}}
	}
	if cfg.Exchange.SMTPHost == "" {
		cfg.Exchange.SMTPHost = "smtp.office365.com:587"
	}
	if cfg.Exchange.GraphEndpoint == "" {
		cfg.Exchange.GraphEndpoint = "https://graph.microsoft.com"
	}
	if cfg.Exchange.TokenScope == "" {
		if cfg.Exchange.Method == MethodGraph {
			cfg.Exchange.TokenScope = strings.TrimSuffix(cfg.Exchange.GraphEndpoint, "/") + "/.default"
		} else {
			cfg.Exchange.TokenScope = "https://outlook.office365.com/.default"
		}
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if c.Hostname == "" {
		fail("hostname is required")
	}
	for _, l := range c.Listeners {
		if l.Mode != ModeImplicit && l.Mode != ModeStartTLS {
			fail("listener %s: mode must be %q or %q", l.Addr, ModeImplicit, ModeStartTLS)
		}
	}
	switch c.TLS.Mode {
	case "files":
		if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
			fail("tls.cert_file and tls.key_file are required when tls.mode is files")
		}
	case "acme":
		if c.TLS.ACME.Email == "" {
			fail("tls.acme.email is required")
		}
		switch c.TLS.ACME.Challenge {
		case ChallengeDNSAzure:
			if c.TLS.ACME.AzureDNS.SubscriptionID == "" || c.TLS.ACME.AzureDNS.ResourceGroup == "" {
				fail("tls.acme.azure_dns.subscription_id and resource_group are required for dns-azure")
			}
		case ChallengeHTTP01:
		default:
			fail("tls.acme.challenge must be %q or %q", ChallengeDNSAzure, ChallengeHTTP01)
		}
	default:
		fail("tls.mode must be acme or files")
	}
	if c.Exchange.Method != MethodSMTP && c.Exchange.Method != MethodGraph {
		fail("exchange.method must be %q or %q", MethodSMTP, MethodGraph)
	}
	if len(c.Policy.AllowedSenders) == 0 {
		fail(`policy.allowed_senders must not be empty (use "*" to rely on Exchange RBAC scoping alone)`)
	}
	if c.Policy.RequireAuth && len(c.Users) == 0 {
		fail("policy.require_auth is true but no users are configured")
	}
	seen := map[string]bool{}
	for _, u := range c.Users {
		if u.Username == "" {
			fail("user with empty username")
		}
		if seen[u.Username] {
			fail("duplicate user %q", u.Username)
		}
		seen[u.Username] = true
		if !strings.HasPrefix(u.PasswordHash, "$2") {
			fail("user %q: password_hash must be a bcrypt hash (see `smtp2m365 hash-password`)", u.Username)
		}
	}
	if c.Admin.Addr != "" && c.Admin.Token == "" && !isLoopback(c.Admin.Addr) {
		fail("admin.token is required when admin.addr is not a loopback address")
	}
	return errors.Join(errs...)
}

func isLoopback(addr string) bool {
	return strings.HasPrefix(addr, "127.") || strings.HasPrefix(addr, "localhost:") || strings.HasPrefix(addr, "[::1]:")
}
