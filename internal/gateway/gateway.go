// Package gateway runs the SMTP listeners and relays accepted messages to
// Exchange Online.
package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/emersion/go-smtp"
	"golang.org/x/sync/errgroup"

	"smtp2m365/internal/auth"
	"smtp2m365/internal/config"
	"smtp2m365/internal/exchange"
	"smtp2m365/internal/policy"
	"smtp2m365/internal/report"
)

type Gateway struct {
	cfg     *config.Config
	policy  *policy.Policy
	users   *auth.Store
	sender  exchange.Sender
	rec     *report.Recorder
	limiter *failureLimiter
	log     *slog.Logger
}

func New(cfg *config.Config, pol *policy.Policy, users *auth.Store, sender exchange.Sender, rec *report.Recorder, log *slog.Logger) *Gateway {
	return &Gateway{
		cfg:     cfg,
		policy:  pol,
		users:   users,
		sender:  sender,
		rec:     rec,
		limiter: newFailureLimiter(cfg.Policy.MaxAuthFailures, cfg.Policy.AuthFailureWindow),
		log:     log,
	}
}

// Run serves all configured listeners until ctx is cancelled or one of
// them fails.
func (g *Gateway) Run(ctx context.Context, tlsCfg *tls.Config) error {
	var listeners []Listener
	for _, l := range g.cfg.Listeners {
		ln, err := net.Listen("tcp", l.Addr)
		if err != nil {
			for _, bound := range listeners {
				bound.Listener.Close()
			}
			return err
		}
		listeners = append(listeners, Listener{Listener: ln, Mode: l.Mode})
	}
	return g.Serve(ctx, tlsCfg, listeners)
}

// Listener is a bound socket plus its TLS mode.
type Listener struct {
	net.Listener
	Mode string
}

func (g *Gateway) Serve(ctx context.Context, tlsCfg *tls.Config, listeners []Listener) error {
	grp, ctx := errgroup.WithContext(ctx)
	var servers []*smtp.Server

	for _, l := range listeners {
		addr := l.Addr().String()
		srv := smtp.NewServer(&backend{g: g, listener: addr})
		srv.Domain = g.cfg.Hostname
		srv.TLSConfig = tlsCfg
		srv.AllowInsecureAuth = false
		srv.MaxMessageBytes = g.cfg.Limits.MaxMessageBytes
		srv.MaxRecipients = g.cfg.Limits.MaxRecipients
		srv.ReadTimeout = 2 * time.Minute
		srv.WriteTimeout = time.Minute

		var ln net.Listener = &filteredListener{Listener: l.Listener, allow: g.policy.ClientAllowed, onDrop: g.rec.CountDropped}
		if l.Mode == config.ModeImplicit {
			ln = tls.NewListener(ln, tlsCfg)
		}
		servers = append(servers, srv)
		g.log.Info("listening", "addr", addr, "mode", l.Mode)
		grp.Go(func() error {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, smtp.ErrServerClosed) {
				return err
			}
			return nil
		})
	}

	grp.Go(func() error {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, srv := range servers {
			_ = srv.Shutdown(shutdownCtx)
		}
		return nil
	})
	return grp.Wait()
}

// filteredListener drops connections from disallowed IPs before any TLS
// handshake or SMTP greeting happens.
type filteredListener struct {
	net.Listener
	allow  func(netip.Addr) bool
	onDrop func()
}

func (l *filteredListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.allow(remoteIP(c)) {
			return c, nil
		}
		l.onDrop()
		c.Close()
	}
}

func remoteIP(c net.Conn) netip.Addr {
	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}
