package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"golang.org/x/crypto/bcrypt"

	"github.com/leonhament/smtp2m365/internal/auth"
	"github.com/leonhament/smtp2m365/internal/config"
	"github.com/leonhament/smtp2m365/internal/exchange"
	"github.com/leonhament/smtp2m365/internal/policy"
	"github.com/leonhament/smtp2m365/internal/report"
)

type sent struct {
	mailbox    string
	recipients []string
	msg        string
}

type fakeSender struct {
	mu   sync.Mutex
	sent []sent
	err  error
}

func (f *fakeSender) Send(_ context.Context, mailbox string, recipients []string, msg []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, sent{mailbox, recipients, string(msg)})
	return nil
}

type harness struct {
	starttls, implicit string
	sender             *fakeSender
	rec                *report.Recorder
}

func start(t *testing.T, networks []string) *harness {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("correct horse"), bcrypt.MinCost)
	cfg := &config.Config{
		Hostname: "smtp.test",
		Exchange: config.Exchange{Timeout: 5 * time.Second},
		Policy: config.Policy{
			RequireAuth:       true,
			CheckHeaderFrom:   true,
			MaxAuthFailures:   3,
			AuthFailureWindow: time.Minute,
		},
		Limits: config.Limits{MaxMessageBytes: 1 << 20, MaxRecipients: 10},
	}
	pol, err := policy.New(networks, []string{"@contoso.com"}, []string{"ceo@contoso.com"})
	if err != nil {
		t.Fatal(err)
	}
	users, _ := auth.NewStore([]config.User{
		{Username: "printer", PasswordHash: string(hash)},
		{Username: "scanner", PasswordHash: string(hash), AllowedSenders: []string{"scan@contoso.com"}},
	})
	h := &harness{sender: &fakeSender{}, rec: report.New(slog.New(slog.NewTextHandler(io.Discard, nil)), 100)}
	g := New(cfg, pol, users, h.sender, h.rec, slog.New(slog.NewTextHandler(io.Discard, nil)))

	l1, _ := net.Listen("tcp", "127.0.0.1:0")
	l2, _ := net.Listen("tcp", "127.0.0.1:0")
	h.starttls, h.implicit = l1.Addr().String(), l2.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = g.Serve(ctx, selfSigned(t), []Listener{{l1, config.ModeStartTLS}, {l2, config.ModeImplicit}})
	}()
	t.Cleanup(func() { cancel(); <-done })
	return h
}

var clientTLS = &tls.Config{InsecureSkipVerify: true}

func (h *harness) dial(t *testing.T, user string) *smtp.Client {
	t.Helper()
	c, err := smtp.DialStartTLS(h.starttls, clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if user != "" {
		if err := c.Auth(sasl.NewPlainClient("", user, "correct horse")); err != nil {
			t.Fatalf("auth: %v", err)
		}
	}
	return c
}

func message(from, to string) string {
	return "From: " + from + "\r\nTo: " + to + "\r\nSubject: test\r\n\r\nhello\r\n"
}

func code(err error) int {
	var se *smtp.SMTPError
	if errors.As(err, &se) {
		return se.Code
	}
	return 0
}

func TestRelaysAuthenticatedMessage(t *testing.T) {
	h := start(t, []string{"127.0.0.0/8"})
	c := h.dial(t, "printer")
	err := c.SendMail("scan@contoso.com", []string{"alice@example.com", "hidden@example.com"},
		strings.NewReader(message("scan@contoso.com", "alice@example.com")))
	if err != nil {
		t.Fatalf("SendMail: %v", err)
	}
	if len(h.sender.sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(h.sender.sent))
	}
	got := h.sender.sent[0]
	if got.mailbox != "scan@contoso.com" || len(got.recipients) != 2 {
		t.Errorf("relayed as %q to %v", got.mailbox, got.recipients)
	}
	if !strings.HasPrefix(got.msg, "Message-ID: <") {
		t.Errorf("Message-ID not added:\n%s", got.msg)
	}
	if ev := h.rec.Recent(1)[0]; ev.Outcome != report.Delivered || ev.User != "printer" || ev.MessageID == "" {
		t.Errorf("report event = %+v", ev)
	}
}

func TestImplicitTLS(t *testing.T) {
	h := start(t, []string{"127.0.0.0/8"})
	c, err := smtp.DialTLS(h.implicit, clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Auth(sasl.NewPlainClient("", "printer", "correct horse")); err != nil {
		t.Fatal(err)
	}
	if err := c.SendMail("a@contoso.com", []string{"b@example.com"}, strings.NewReader(message("a@contoso.com", "b@example.com"))); err != nil {
		t.Fatal(err)
	}
}

func TestRequiresTLS(t *testing.T) {
	h := start(t, []string{"127.0.0.0/8"})
	c, err := smtp.Dial(h.starttls)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if ok, _ := c.Extension("AUTH"); ok {
		t.Error("AUTH advertised before STARTTLS")
	}
	if err := c.Mail("a@contoso.com", nil); code(err) != 530 {
		t.Errorf("MAIL without TLS: %v, want 530", err)
	}
}

func TestPolicyRejections(t *testing.T) {
	h := start(t, []string{"127.0.0.0/8"})
	cases := []struct {
		name, user, envFrom, hdrFrom string
		want                         int
	}{
		{"no auth", "", "a@contoso.com", "a@contoso.com", 530},
		{"denied sender", "printer", "ceo@contoso.com", "ceo@contoso.com", 550},
		{"foreign domain", "printer", "a@evil.com", "a@evil.com", 550},
		{"header From spoof", "printer", "a@contoso.com", "ceo@contoso.com", 550},
		{"per-user restriction", "scanner", "printer@contoso.com", "printer@contoso.com", 550},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := h.dial(t, tc.user)
			err := c.SendMail(tc.envFrom, []string{"x@example.com"}, strings.NewReader(message(tc.hdrFrom, "x@example.com")))
			if code(err) != tc.want {
				t.Errorf("err = %v, want %d", err, tc.want)
			}
		})
	}
	if len(h.sender.sent) != 0 {
		t.Errorf("%d rejected messages were relayed", len(h.sender.sent))
	}
}

func TestRelayErrorsMapToSMTPCodes(t *testing.T) {
	h := start(t, []string{"127.0.0.0/8"})
	for _, tc := range []struct {
		err  error
		want int
	}{
		{&exchange.Error{Temporary: true, Err: errors.New("throttled")}, 451},
		{&exchange.Error{Temporary: false, Err: errors.New("550 5.7.60 SendAsDenied")}, 554},
		{&exchange.Error{Err: exchange.ErrTooLargeForGraph}, 552},
	} {
		h.sender.err = tc.err
		c := h.dial(t, "printer")
		err := c.SendMail("a@contoso.com", []string{"b@example.com"}, strings.NewReader(message("a@contoso.com", "b@example.com")))
		if code(err) != tc.want {
			t.Errorf("%v: got %v, want %d", tc.err, err, tc.want)
		}
	}
}

func TestAuthFailureLockout(t *testing.T) {
	h := start(t, []string{"127.0.0.0/8"})
	for i := 0; i < 3; i++ {
		c, err := smtp.DialStartTLS(h.starttls, clientTLS)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Auth(sasl.NewPlainClient("", "printer", "wrong")); code(err) != 535 {
			t.Errorf("attempt %d: %v, want 535", i, err)
		}
		c.Close()
	}
	if _, err := smtp.DialStartTLS(h.starttls, clientTLS); code(err) != 421 {
		t.Errorf("after lockout: %v, want 421", err)
	}
}

func TestDisallowedNetworkIsDropped(t *testing.T) {
	h := start(t, []string{"10.0.0.0/8"})
	if c, err := smtp.DialStartTLS(h.starttls, clientTLS); err == nil {
		c.Close()
		t.Fatal("connection from disallowed IP was accepted")
	}
	if h.rec.Stats().DroppedConnections == 0 {
		t.Error("dropped connection not counted")
	}
}

func selfSigned(t *testing.T) *tls.Config {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "smtp.test"},
		DNSNames:     []string{"smtp.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}
