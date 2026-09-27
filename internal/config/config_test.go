package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadExample(t *testing.T) {
	t.Setenv("PRINTER_FLOOR2_HASH", "$2a$12$abcdefghijklmnopqrstuuJ8m0Qy3oYdCkCQn0pT5c5aQy0x1Xy2e")
	t.Setenv("ADMIN_TOKEN", "t")
	cfg, err := Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cfg.Users[0].PasswordHash, "$2a$12$") {
		t.Errorf("env expansion mangled the bcrypt hash: %q", cfg.Users[0].PasswordHash)
	}
	if cfg.Exchange.TokenScope != "https://outlook.office365.com/.default" {
		t.Errorf("token scope = %q", cfg.Exchange.TokenScope)
	}
}

// The Bicep template writes the config as JSON, which must load as YAML.
func TestLoadJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	os.WriteFile(path, []byte(`{"hostname":"smtp.contoso.com","listeners":[{"addr":":465","mode":"implicit"}],
"tls":{"mode":"acme","acme":{"email":"a@contoso.com","staging":false,"challenge":"dns-azure","storage":"/data/certmagic",
"azure_dns":{"subscription_id":"s","resource_group":"rg"}}},"exchange":{"method":"smtp"},
"policy":{"allowed_networks":["198.51.100.0/24"],"require_auth":true,"allowed_senders":["@contoso.com"],"denied_senders":[],"check_header_from":true},
"users":[{"username":"p","password_hash":"$2a$12$abcdefghijklmnopqrstuuJ8m0Qy3oYdCkCQn0pT5c5aQy0x1Xy2e","allowed_senders":["scan@contoso.com"]}],
"admin":{"addr":"127.0.0.1:8080"}}`), 0o600)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Users[0].AllowedSenders[0] != "scan@contoso.com" || cfg.Policy.MaxAuthFailures != 10 {
		t.Errorf("unexpected config: %+v", cfg)
	}
}

func TestValidation(t *testing.T) {
	cases := map[string]string{
		"missing hostname": `
tls: {mode: files, cert_file: a, key_file: b}
policy: {allowed_senders: ["*"], require_auth: false}`,
		"empty allowed_senders": `
hostname: x
tls: {mode: files, cert_file: a, key_file: b}
policy: {require_auth: false}`,
		"auth without users": `
hostname: x
tls: {mode: files, cert_file: a, key_file: b}
policy: {allowed_senders: ["*"]}`,
		"plaintext hash": `
hostname: x
tls: {mode: files, cert_file: a, key_file: b}
policy: {allowed_senders: ["*"]}
users: [{username: u, password_hash: hunter2}]`,
		"unknown field": `
hostname: x
tls: {mode: files, cert_file: a, key_file: b}
policy: {allowed_senders: ["*"], require_auth: false, alowed_networks: []}`,
		"challenge alias without _acme-challenge prefix": `
hostname: x
tls: {mode: acme, acme: {email: a@b.c, challenge: dns-azure, challenge_alias: smtp2m365.bytecloud.nl, azure_dns: {subscription_id: s, resource_group: r}}}
policy: {allowed_senders: ["*"], require_auth: false}`,
		"challenge alias with http-01": `
hostname: x
tls: {mode: acme, acme: {email: a@b.c, challenge: http-01, challenge_alias: _acme-challenge.x.y}}
policy: {allowed_senders: ["*"], require_auth: false}`,
		"public admin without token": `
hostname: x
tls: {mode: files, cert_file: a, key_file: b}
policy: {allowed_senders: ["*"], require_auth: false}
admin: {addr: ":8080"}`,
	}
	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "c.yaml")
			os.WriteFile(path, []byte(yaml), 0o600)
			if _, err := Load(path); err == nil {
				t.Error("expected an error")
			}
		})
	}
}
