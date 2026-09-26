package exchange

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/emersion/go-smtp"
)

// smtpSender uses SMTP client submission (smtp.office365.com:587) with an
// app-only OAuth token. The raw message is passed through unchanged, so
// envelope recipients, Bcc and large attachments behave exactly like SMTP.
type smtpSender struct {
	host      string
	scope     string
	localName string
	cred      azcore.TokenCredential
}

func (s *smtpSender) Send(ctx context.Context, mailbox string, recipients []string, msg []byte) error {
	tok, err := s.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{s.scope}})
	if err != nil {
		return &Error{Temporary: true, Err: fmt.Errorf("acquire token: %w", err)}
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", s.host)
	if err != nil {
		return &Error{Temporary: true, Err: fmt.Errorf("connect %s: %w", s.host, err)}
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	serverName, _, _ := net.SplitHostPort(s.host)
	// go-smtp greets with "localhost" here; Exchange Online does not care.
	c, err := smtp.NewClientStartTLS(conn, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12})
	if err != nil {
		conn.Close()
		return &Error{Temporary: true, Err: fmt.Errorf("starttls: %w", err)}
	}
	defer c.Close()

	if err := c.Auth(&xoauth2{user: mailbox, token: tok.Token}); err != nil {
		// Usually missing/propagating RBAC (the role cache takes up to 2h)
		// or SMTP AUTH disabled on the mailbox. Temporary, so fixing the
		// config lets queued client retries succeed.
		return &Error{Temporary: true, Err: fmt.Errorf("xoauth2 as %s: %w", mailbox, err)}
	}
	if err := c.SendMail(mailbox, recipients, bytes.NewReader(msg)); err != nil {
		return classifySMTP(err)
	}
	_ = c.Quit()
	return nil
}

func classifySMTP(err error) error {
	var se *smtp.SMTPError
	if errors.As(err, &se) {
		return &Error{Temporary: se.Code/100 == 4, Err: fmt.Errorf("exchange online: %w", err)}
	}
	return &Error{Temporary: true, Err: err}
}

// xoauth2 is the SASL XOAUTH2 client mechanism used by Exchange Online.
type xoauth2 struct{ user, token string }

func (a *xoauth2) Start() (string, []byte, error) {
	return "XOAUTH2", []byte("user=" + a.user + "\x01auth=Bearer " + a.token + "\x01\x01"), nil
}

func (a *xoauth2) Next(challenge []byte) ([]byte, error) {
	// A challenge after the initial response carries a JSON error.
	return nil, fmt.Errorf("xoauth2 rejected: %s", challenge)
}
