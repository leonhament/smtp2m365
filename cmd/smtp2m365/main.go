// Command smtp2m365 is a TLS-only SMTP gateway that relays mail from
// devices and legacy applications through Exchange Online.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"golang.org/x/term"

	"smtp2m365/internal/auth"
	"smtp2m365/internal/config"
	"smtp2m365/internal/exchange"
	"smtp2m365/internal/gateway"
	"smtp2m365/internal/policy"
	"smtp2m365/internal/report"
	"smtp2m365/internal/tlsconf"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "hash-password":
			if err := hashPassword(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		case "version":
			fmt.Println(version)
			return
		}
	}

	configPath := flag.String("config", "/etc/smtp2m365/config.yaml", "path to the configuration file")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, *configPath, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, configPath string, log *slog.Logger) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	pol, err := policy.New(cfg.Policy.AllowedNetworks, cfg.Policy.AllowedSenders, cfg.Policy.DeniedSenders)
	if err != nil {
		return err
	}
	if len(cfg.Policy.AllowedNetworks) == 0 {
		log.Warn("policy.allowed_networks is empty; every connection will be refused")
	}
	users, err := auth.NewStore(cfg.Users)
	if err != nil {
		return err
	}

	// Managed identity in Azure; AZURE_TENANT_ID/AZURE_CLIENT_ID/
	// AZURE_CLIENT_SECRET (or a certificate) elsewhere or for cross-tenant use.
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("azure credential: %w", err)
	}
	sender, err := exchange.New(cfg.Exchange, cfg.Hostname, cred)
	if err != nil {
		return err
	}
	rec := report.New(log, cfg.Reporting.RecentEvents)

	// Start the admin endpoint first so health checks work while the
	// certificate is being obtained.
	if cfg.Admin.Addr != "" {
		srv := &http.Server{Addr: cfg.Admin.Addr, Handler: rec.Handler(cfg.Admin.Token), ReadHeaderTimeout: 10 * time.Second}
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("admin server", "err", err)
			}
		}()
		defer srv.Close()
	}

	tlsCfg, err := tlsconf.Load(ctx, cfg.Hostname, cfg.TLS)
	if err != nil {
		return err
	}

	log.Info("smtp2m365 starting", "version", version, "hostname", cfg.Hostname, "exchange_method", cfg.Exchange.Method)
	return gateway.New(cfg, pol, users, sender, rec, log).Run(ctx, tlsCfg)
}

func hashPassword() error {
	var password string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Password: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		password = string(b)
	} else {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return err
		}
		password = strings.TrimRight(line, "\r\n")
	}
	if len(password) < 12 {
		return errors.New("use a password of at least 12 characters")
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	fmt.Println(hash)
	return nil
}
