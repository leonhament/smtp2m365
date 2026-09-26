package auth

import (
	"errors"
	"testing"

	"smtp2m365/internal/config"
)

func TestAuthenticate(t *testing.T) {
	hash, err := HashPassword("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewStore([]config.User{{Username: "printer", PasswordHash: hash, AllowedSenders: []string{"scan@contoso.com"}}})
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.Authenticate("printer", "s3cret")
	if err != nil {
		t.Fatalf("valid credentials rejected: %v", err)
	}
	if !u.Senders.Match("scan@contoso.com") || u.Senders.Match("other@contoso.com") {
		t.Error("per-user sender matcher not applied")
	}
	if _, err := s.Authenticate("printer", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong password: err = %v", err)
	}
	if _, err := s.Authenticate("nobody", "s3cret"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("unknown user: err = %v", err)
	}
}

func TestLoginServer(t *testing.T) {
	var gotUser, gotPass string
	check := func(u, p string) error { gotUser, gotPass = u, p; return nil }

	t.Run("without initial response", func(t *testing.T) {
		s := NewLoginServer(check)
		if ch, done, _ := s.Next(nil); string(ch) != "Username:" || done {
			t.Fatalf("step 0: %q %v", ch, done)
		}
		if ch, done, _ := s.Next([]byte("alice")); string(ch) != "Password:" || done {
			t.Fatalf("step 1: %q %v", ch, done)
		}
		if _, done, err := s.Next([]byte("pw")); !done || err != nil {
			t.Fatalf("step 2: %v %v", done, err)
		}
		if gotUser != "alice" || gotPass != "pw" {
			t.Errorf("got %q/%q", gotUser, gotPass)
		}
	})

	t.Run("with initial response", func(t *testing.T) {
		s := NewLoginServer(check)
		if ch, _, _ := s.Next([]byte("bob")); string(ch) != "Password:" {
			t.Fatalf("step 0: %q", ch)
		}
		if _, done, err := s.Next([]byte("pw2")); !done || err != nil {
			t.Fatalf("step 1: %v %v", done, err)
		}
		if gotUser != "bob" || gotPass != "pw2" {
			t.Errorf("got %q/%q", gotUser, gotPass)
		}
	})
}
