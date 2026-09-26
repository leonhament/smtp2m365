package exchange

import (
	"strings"
	"testing"
)

func TestWithEnvelopeRecipients(t *testing.T) {
	msg := []byte("From: scan@contoso.com\r\nTo: Alice <alice@contoso.com>\r\nCc: bob@contoso.com\r\nSubject: hi\r\n\r\nbody\r\n")

	got := withEnvelopeRecipients(msg, []string{"ALICE@contoso.com", "bob@contoso.com"})
	if string(got) != string(msg) {
		t.Errorf("message changed although all recipients are in headers:\n%s", got)
	}

	got = withEnvelopeRecipients(msg, []string{"alice@contoso.com", "hidden@contoso.com", "audit@contoso.com"})
	if !strings.HasPrefix(string(got), "Bcc: hidden@contoso.com, audit@contoso.com\r\n") {
		t.Errorf("missing Bcc header:\n%s", got)
	}
	if !strings.HasSuffix(string(got), string(msg)) {
		t.Error("original message not preserved")
	}
}
