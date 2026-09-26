// Package auth verifies SMTP AUTH credentials of devices and applications
// that submit mail to the gateway.
package auth

import (
	"errors"
	"fmt"
	"sync"

	"github.com/emersion/go-sasl"
	"golang.org/x/crypto/bcrypt"

	"smtp2m365/internal/config"
	"smtp2m365/internal/policy"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

type User struct {
	Name string
	// Senders restricts the sender addresses this user may use; nil means
	// only the global policy applies.
	Senders *policy.Matcher
	hash    []byte
}

type Store struct {
	users map[string]*User
}

func NewStore(users []config.User) (*Store, error) {
	s := &Store{users: map[string]*User{}}
	for _, u := range users {
		user := &User{Name: u.Username, hash: []byte(u.PasswordHash)}
		if len(u.AllowedSenders) > 0 {
			m, err := policy.NewMatcher(u.AllowedSenders)
			if err != nil {
				return nil, fmt.Errorf("user %q: %w", u.Username, err)
			}
			user.Senders = m
		}
		s.users[u.Username] = user
	}
	return s, nil
}

// dummyHash keeps the timing of unknown-user lookups close to that of
// wrong-password lookups.
var dummyHash = sync.OnceValue(func() []byte {
	h, _ := bcrypt.GenerateFromPassword([]byte("smtp2m365-dummy"), bcrypt.DefaultCost)
	return h
})

func (s *Store) Authenticate(username, password string) (*User, error) {
	u, ok := s.users[username]
	if !ok {
		_ = bcrypt.CompareHashAndPassword(dummyHash(), []byte(password))
		return nil, ErrInvalidCredentials
	}
	if bcrypt.CompareHashAndPassword(u.hash, []byte(password)) != nil {
		return nil, ErrInvalidCredentials
	}
	return u, nil
}

func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(h), err
}

// NewLoginServer implements the (non-standard but ubiquitous) LOGIN SASL
// mechanism, which many printers and scanners only support. go-sasl only
// ships a LOGIN client.
func NewLoginServer(authenticate func(username, password string) error) sasl.Server {
	return &loginServer{authenticate: authenticate}
}

type loginServer struct {
	step         int
	username     string
	authenticate func(username, password string) error
}

func (s *loginServer) Next(response []byte) (challenge []byte, done bool, err error) {
	switch s.step {
	case 0:
		// Some clients send the username as an initial response.
		if len(response) > 0 {
			s.username, s.step = string(response), 2
			return []byte("Password:"), false, nil
		}
		s.step = 1
		return []byte("Username:"), false, nil
	case 1:
		s.username, s.step = string(response), 2
		return []byte("Password:"), false, nil
	case 2:
		s.step = 3
		return nil, true, s.authenticate(s.username, string(response))
	}
	return nil, false, errors.New("unexpected LOGIN response")
}
