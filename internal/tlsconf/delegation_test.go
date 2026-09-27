package tlsconf

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func fakeDNS(records map[string]string) func(context.Context, string) (string, error) {
	return func(_ context.Context, name string) (string, error) {
		return records[name], nil
	}
}

func TestCheckDelegation(t *testing.T) {
	const host, alias = "smtp.contoso.com", "_acme-challenge.smtp2m365.bytecloud.nl"
	ctx := context.Background()

	ok := fakeDNS(map[string]string{"_acme-challenge.smtp.contoso.com.": "_ACME-challenge.smtp2m365.bytecloud.nl."})
	if err := checkDelegation(ctx, host, alias, ok); err != nil {
		t.Errorf("direct CNAME: %v", err)
	}

	chain := fakeDNS(map[string]string{
		"_acme-challenge.smtp.contoso.com.": "acme.contoso.com.",
		"acme.contoso.com.":                 "_acme-challenge.smtp2m365.bytecloud.nl.",
	})
	if err := checkDelegation(ctx, host, alias, chain); err != nil {
		t.Errorf("CNAME chain: %v", err)
	}

	err := checkDelegation(ctx, host, alias, fakeDNS(nil))
	if err == nil || !strings.Contains(err.Error(), "_acme-challenge.smtp.contoso.com  CNAME  _acme-challenge.smtp2m365.bytecloud.nl") {
		t.Errorf("missing CNAME: error should tell which record to create, got: %v", err)
	}

	wrong := fakeDNS(map[string]string{"_acme-challenge.smtp.contoso.com.": "elsewhere.example."})
	if err := checkDelegation(ctx, host, alias, wrong); err == nil || !strings.Contains(err.Error(), "points to elsewhere.example") {
		t.Errorf("wrong CNAME: %v", err)
	}

	loop := fakeDNS(map[string]string{"_acme-challenge.smtp.contoso.com.": "_acme-challenge.smtp.contoso.com."})
	if err := checkDelegation(ctx, host, alias, loop); err == nil {
		t.Error("CNAME loop should fail")
	}

	failing := func(context.Context, string) (string, error) { return "", errors.New("timeout") }
	if err := checkDelegation(ctx, host, alias, failing); err == nil {
		t.Error("lookup failure should fail")
	}
}
