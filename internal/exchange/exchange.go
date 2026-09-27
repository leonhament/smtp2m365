// Package exchange relays messages to Exchange Online.
//
// Neither method needs an API permission consented in Entra ID. Access is
// granted and scoped in Exchange Online with RBAC for Applications:
//
//   - smtp:  role "Application SMTP.SendAsApp", SMTP client submission with XOAUTH2
//   - graph: role "Application Mail.Send", Microsoft Graph sendMail with MIME
//
// See scripts/Setup-ExchangeRbac.ps1.
package exchange

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/leonhament/smtp2m365/internal/config"
)

// Sender submits a raw RFC 5322 message on behalf of mailbox.
type Sender interface {
	Send(ctx context.Context, mailbox string, recipients []string, msg []byte) error
}

// Error is a relay failure. Temporary failures are reported to the SMTP
// client as 4xx so it can retry; permanent ones as 5xx.
type Error struct {
	Temporary bool
	Err       error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func New(cfg config.Exchange, localName string, cred azcore.TokenCredential) (Sender, error) {
	switch cfg.Method {
	case config.MethodSMTP:
		return &smtpSender{host: cfg.SMTPHost, scope: cfg.TokenScope, localName: localName, cred: cred}, nil
	case config.MethodGraph:
		return newGraphSender(cfg.GraphEndpoint, cfg.TokenScope, cred), nil
	}
	return nil, fmt.Errorf("unknown exchange method %q", cfg.Method)
}
