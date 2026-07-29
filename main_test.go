package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Account files written by lego v4 must keep working after the v5 upgrade:
// losing the account URL would make every subsequent request unauthenticated.
func TestMigrateLegacyAccount(t *testing.T) {
	data := []byte(`{
		"email": "user@example.com",
		"registration": {
			"body": {"status": "valid", "contact": ["mailto:user@example.com"]},
			"uri": "https://acme-v02.api.letsencrypt.org/acme/acct/123"
		}
	}`)

	var account Account
	if err := json.Unmarshal(data, &account); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if account.Registration != nil && account.Registration.Location != "" {
		t.Fatal("legacy file unexpectedly parsed as the current format")
	}

	if err := migrateLegacyAccount(data, &account); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	if got := account.Registration.Location; got != "https://acme-v02.api.letsencrypt.org/acme/acct/123" {
		t.Errorf("Location = %q, want the URI from the legacy file", got)
	}
	if got := account.Registration.Status; got != "valid" {
		t.Errorf("Status = %q, want %q", got, "valid")
	}
}

func TestMigrateLegacyAccountWithoutRegistration(t *testing.T) {
	var account Account
	if err := migrateLegacyAccount([]byte(`{"email": "user@example.com"}`), &account); err == nil {
		t.Error("expected an error for an account file without a registration URL")
	}
}

func TestSlicesEqual(t *testing.T) {
	tests := []struct {
		name string
		a    []string
		b    []string
		want bool
	}{
		{"same order", []string{"a.example.com", "b.example.com"}, []string{"a.example.com", "b.example.com"}, true},
		{"different order", []string{"www.example.com", "api.example.com"}, []string{"api.example.com", "www.example.com"}, true},
		{"different length", []string{"a.example.com"}, []string{"a.example.com", "b.example.com"}, false},
		{"different values", []string{"a.example.com"}, []string{"b.example.com"}, false},
		{"both empty", []string{}, []string{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := slicesEqual(tt.a, tt.b); got != tt.want {
				t.Errorf("slicesEqual(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// The first domain of the list becomes the certificate CommonName, so
// slicesEqual must not reorder the slices it is given.
func TestSlicesEqualDoesNotMutateArguments(t *testing.T) {
	a := []string{"www.example.com", "api.example.com"}
	b := []string{"api.example.com", "www.example.com"}

	if !slicesEqual(a, b) {
		t.Fatal("expected slices to be equal")
	}

	if a[0] != "www.example.com" {
		t.Errorf("first argument was reordered: got %v, CommonName would change to %q", a, a[0])
	}
	if b[0] != "api.example.com" {
		t.Errorf("second argument was reordered: got %v, CommonName would change to %q", b, b[0])
	}
}

func TestCreatePrivateKeyPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cert.key")

	if _, err := createPrivateKey(path); err != nil {
		t.Fatalf("createPrivateKey: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Errorf("private key mode = %04o, want 0600", mode)
	}
}

func TestLoadOrCreatePrivateKeyRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account.key")

	created, err := loadOrCreatePrivateKey(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	loaded, err := loadOrCreatePrivateKey(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if !created.Equal(loaded) {
		t.Error("loaded key does not match the created one")
	}
}
