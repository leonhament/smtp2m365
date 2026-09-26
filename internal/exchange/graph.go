package exchange

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// Graph rejects request bodies over 4 MB, and sendMail with MIME content
// cannot use upload sessions.
const maxGraphBody = 4 << 20

var ErrTooLargeForGraph = errors.New("message exceeds the 4 MB Graph request limit; use exchange.method smtp for large messages")

// graphSender uses POST /users/{mailbox}/sendMail with a base64 MIME body.
type graphSender struct {
	endpoint string
	scope    string
	cred     azcore.TokenCredential
	client   *http.Client
}

func newGraphSender(endpoint, scope string, cred azcore.TokenCredential) *graphSender {
	return &graphSender{endpoint: strings.TrimSuffix(endpoint, "/"), scope: scope, cred: cred, client: &http.Client{}}
}

func (g *graphSender) Send(ctx context.Context, mailbox string, recipients []string, msg []byte) error {
	body := base64.StdEncoding.EncodeToString(withEnvelopeRecipients(msg, recipients))
	if len(body) > maxGraphBody {
		return &Error{Err: ErrTooLargeForGraph}
	}
	tok, err := g.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{g.scope}})
	if err != nil {
		return &Error{Temporary: true, Err: fmt.Errorf("acquire token: %w", err)}
	}

	u := g.endpoint + "/v1.0/users/" + url.PathEscape(mailbox) + "/sendMail"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(body))
	if err != nil {
		return &Error{Err: err}
	}
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	req.Header.Set("Content-Type", "text/plain")

	resp, err := g.client.Do(req)
	if err != nil {
		return &Error{Temporary: true, Err: fmt.Errorf("graph sendMail: %w", err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusAccepted {
		return nil
	}
	detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return &Error{
		Temporary: resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500,
		Err:       fmt.Errorf("graph sendMail: %s: %s", resp.Status, bytes.TrimSpace(detail)),
	}
}

// withEnvelopeRecipients adds a Bcc header for envelope recipients that do
// not appear in To/Cc/Bcc. Graph derives recipients from the MIME headers,
// so without this, envelope-only recipients (how SMTP clients send Bcc)
// would silently be dropped.
func withEnvelopeRecipients(msg []byte, recipients []string) []byte {
	listed := map[string]bool{}
	if m, err := mail.ReadMessage(bytes.NewReader(msg)); err == nil {
		for _, h := range []string{"To", "Cc", "Bcc"} {
			addrs, _ := m.Header.AddressList(h)
			for _, a := range addrs {
				listed[strings.ToLower(a.Address)] = true
			}
		}
	}
	var missing []string
	for _, r := range recipients {
		if !listed[strings.ToLower(r)] {
			missing = append(missing, r)
		}
	}
	if len(missing) == 0 {
		return msg
	}
	return append([]byte("Bcc: "+strings.Join(missing, ", ")+"\r\n"), msg...)
}
