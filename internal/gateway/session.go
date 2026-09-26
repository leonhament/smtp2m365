package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"net/netip"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"smtp2m365/internal/auth"
	"smtp2m365/internal/exchange"
	"smtp2m365/internal/policy"
	"smtp2m365/internal/report"
)

var (
	errTLSRequired  = &smtp.SMTPError{Code: 530, EnhancedCode: smtp.EnhancedCode{5, 7, 0}, Message: "Must issue a STARTTLS command first"}
	errAuthRequired = &smtp.SMTPError{Code: 530, EnhancedCode: smtp.EnhancedCode{5, 7, 0}, Message: "Authentication required"}
	errTooManyFails = &smtp.SMTPError{Code: 421, EnhancedCode: smtp.EnhancedCode{4, 7, 0}, Message: "Too many failed authentication attempts, try again later"}
	errSender       = &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "Sender address rejected by policy"}
	errMalformed    = &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 6, 0}, Message: "Malformed message headers"}
	errTooLarge     = &smtp.SMTPError{Code: 552, EnhancedCode: smtp.EnhancedCode{5, 3, 4}, Message: "Message too large for the configured relay method"}
	errRelayTemp    = &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 4, 0}, Message: "Temporary failure relaying to Exchange Online, try again later"}
)

type backend struct {
	g        *Gateway
	listener string
}

func (b *backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	ip := remoteIP(c.Conn())
	if b.g.limiter.Blocked(ip) {
		return nil, errTooManyFails
	}
	return &session{g: b.g, conn: c, ip: ip, listener: b.listener}, nil
}

// session handles one SMTP connection, which may carry several messages.
type session struct {
	g        *Gateway
	conn     *smtp.Conn
	ip       netip.Addr
	listener string
	user     *auth.User

	// per message
	id    string
	start time.Time
	from  string
	rcpts []string
}

func (s *session) AuthMechanisms() []string {
	return []string{sasl.Plain, "LOGIN"}
}

func (s *session) Auth(mech string) (sasl.Server, error) {
	if s.g.limiter.Blocked(s.ip) {
		return nil, errTooManyFails
	}
	check := func(username, password string) error {
		u, err := s.g.users.Authenticate(username, password)
		if err != nil {
			s.g.limiter.Fail(s.ip)
			s.record(report.Event{Stage: "auth", Outcome: report.Rejected, User: username, Reason: err.Error()})
			return smtp.ErrAuthFailed
		}
		s.g.limiter.Reset(s.ip)
		s.user = u
		return nil
	}
	switch mech {
	case sasl.Plain:
		return sasl.NewPlainServer(func(identity, username, password string) error {
			if identity != "" && identity != username {
				return smtp.ErrAuthFailed
			}
			return check(username, password)
		}), nil
	case "LOGIN":
		return auth.NewLoginServer(check), nil
	}
	return nil, smtp.ErrAuthUnsupported
}

func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	s.Reset()
	s.id = newID()
	s.start = time.Now()

	if _, ok := s.conn.TLSConnectionState(); !ok {
		s.reject("mail", from, "TLS required")
		return errTLSRequired
	}
	if s.g.cfg.Policy.RequireAuth && s.user == nil {
		s.reject("mail", from, "authentication required")
		return errAuthRequired
	}
	if err := s.g.policy.CheckSender(from, s.userSenders()); err != nil {
		s.reject("mail", from, err.Error())
		return errSender
	}
	s.from = policy.Normalize(from)
	return nil
}

func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	s.rcpts = append(s.rcpts, to)
	return nil
}

func (s *session) Data(r io.Reader) error {
	msg, err := io.ReadAll(r)
	if err != nil {
		return err // go-smtp reports oversized messages itself
	}
	ev := report.Event{Stage: "data", From: s.from, Recipients: s.rcpts, Size: len(msg)}

	parsed, err := mail.ReadMessage(bytes.NewReader(msg))
	if err != nil {
		ev.Outcome, ev.Reason = report.Rejected, "malformed headers: "+err.Error()
		s.record(ev)
		return errMalformed
	}
	headerFrom, _ := parsed.Header.AddressList("From")
	for _, a := range headerFrom {
		ev.HeaderFrom = append(ev.HeaderFrom, a.Address)
	}
	if s.g.cfg.Policy.CheckHeaderFrom {
		if len(headerFrom) == 0 {
			ev.Outcome, ev.Reason = report.Rejected, "missing From header"
			s.record(ev)
			return errSender
		}
		for _, a := range headerFrom {
			if err := s.g.policy.CheckSender(a.Address, s.userSenders()); err != nil {
				ev.Outcome, ev.Reason = report.Rejected, "header From: "+err.Error()
				s.record(ev)
				return errSender
			}
		}
	}

	// Many devices omit Message-ID. Adding one makes every message
	// findable in Exchange Online message trace from the report.
	ev.MessageID = parsed.Header.Get("Message-Id")
	if ev.MessageID == "" {
		ev.MessageID = fmt.Sprintf("<%s@%s>", s.id, s.g.cfg.Hostname)
		msg = append([]byte("Message-ID: "+ev.MessageID+"\r\n"), msg...)
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.g.cfg.Exchange.Timeout)
	defer cancel()
	if err := s.g.sender.Send(ctx, s.from, s.rcpts, msg); err != nil {
		ev.Stage, ev.Outcome, ev.Reason = "relay", report.Failed, err.Error()
		s.record(ev)
		return relayError(err)
	}
	ev.Stage, ev.Outcome = "relay", report.Delivered
	s.record(ev)
	return nil
}

func relayError(err error) error {
	if errors.Is(err, exchange.ErrTooLargeForGraph) {
		return errTooLarge
	}
	var xe *exchange.Error
	if !errors.As(err, &xe) || xe.Temporary {
		return errRelayTemp
	}
	// Pass Exchange Online's reason through so admins can see it on the device.
	msg := strings.Join(strings.Fields(xe.Error()), " ")
	return &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 0, 0}, Message: "Rejected by Exchange Online: " + msg}
}

func (s *session) Reset() {
	s.from, s.rcpts = "", nil
}

func (s *session) Logout() error { return nil }

func (s *session) userSenders() *policy.Matcher {
	if s.user == nil {
		return nil
	}
	return s.user.Senders
}

func (s *session) reject(stage, from, reason string) {
	s.record(report.Event{Stage: stage, From: from, Outcome: report.Rejected, Reason: reason})
}

func (s *session) record(e report.Event) {
	e.ID = s.id
	e.RemoteIP = s.ip.String()
	e.Listener = s.listener
	if s.user != nil && e.User == "" {
		e.User = s.user.Name
	}
	if !s.start.IsZero() {
		e.DurationMS = time.Since(s.start).Milliseconds()
	}
	s.g.rec.Record(e)
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
