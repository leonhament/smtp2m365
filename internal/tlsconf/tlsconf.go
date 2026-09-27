// Package tlsconf provides the server TLS configuration, either from
// Let's Encrypt (with automatic renewal) or from certificate files.
package tlsconf

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/azure"

	"github.com/leonhament/smtp2m365/internal/config"
)

func Load(ctx context.Context, hostname string, cfg config.TLS) (*tls.Config, error) {
	var tc *tls.Config
	switch cfg.Mode {
	case "acme":
		var err error
		if tc, err = acme(ctx, hostname, cfg.ACME); err != nil {
			return nil, err
		}
	case "files":
		r := &fileReloader{certFile: cfg.CertFile, keyFile: cfg.KeyFile}
		if _, err := r.GetCertificate(nil); err != nil {
			return nil, err
		}
		tc = &tls.Config{GetCertificate: r.GetCertificate}
	default:
		return nil, fmt.Errorf("unknown tls mode %q", cfg.Mode)
	}
	tc.MinVersion = tls.VersionTLS12
	return tc, nil
}

// acme obtains a certificate for hostname and keeps renewing it in the
// background for as long as the process runs. The storage directory must
// be persistent, otherwise every restart requests a new certificate and
// quickly runs into Let's Encrypt rate limits.
func acme(ctx context.Context, hostname string, cfg config.ACME) (*tls.Config, error) {
	certmagic.Default.Storage = &certmagic.FileStorage{Path: cfg.Storage}
	magic := certmagic.NewDefault()

	issuer := certmagic.ACMEIssuer{
		CA:                      certmagic.LetsEncryptProductionCA,
		Email:                   cfg.Email,
		Agreed:                  true,
		DisableTLSALPNChallenge: true, // port 443 is not ours
	}
	if cfg.Staging {
		issuer.CA = certmagic.LetsEncryptStagingCA
	}
	switch cfg.Challenge {
	case config.ChallengeDNSAzure:
		// Authenticates with the managed identity; it needs the
		// "DNS Zone Contributor" role on the zone.
		issuer.DisableHTTPChallenge = true
		issuer.DNS01Solver = &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{
			DNSProvider: &azure.Provider{
				SubscriptionId:    cfg.AzureDNS.SubscriptionID,
				ResourceGroupName: cfg.AzureDNS.ResourceGroup,
			},
		}}
	case config.ChallengeHTTP01:
		// certmagic binds :80 itself while solving the challenge.
	}
	magic.Issuers = []certmagic.Issuer{certmagic.NewACMEIssuer(magic, issuer)}

	if err := magic.ManageSync(ctx, []string{hostname}); err != nil {
		return nil, fmt.Errorf("obtain certificate for %s: %w", hostname, err)
	}
	tc := magic.TLSConfig()
	tc.NextProtos = nil
	return tc, nil
}

// fileReloader picks up renewed certificate files (e.g. written by an
// external ACME client) without a restart.
type fileReloader struct {
	certFile, keyFile string

	mu      sync.Mutex
	cert    *tls.Certificate
	modTime time.Time
	checked time.Time
}

func (r *fileReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cert != nil && time.Since(r.checked) < time.Minute {
		return r.cert, nil
	}
	r.checked = time.Now()
	st, err := os.Stat(r.certFile)
	if err != nil {
		if r.cert != nil {
			return r.cert, nil
		}
		return nil, err
	}
	if r.cert != nil && st.ModTime().Equal(r.modTime) {
		return r.cert, nil
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		if r.cert != nil {
			return r.cert, nil // keep serving the old one mid-rotation
		}
		return nil, err
	}
	r.cert, r.modTime = &cert, st.ModTime()
	return r.cert, nil
}
