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

func TestValidateCertName(t *testing.T) {
	tests := []struct {
		name     string
		certName string
		wantErr  bool
	}{
		{"simple", "cert", false},
		{"domain", "example.com", false},
		{"repeated dots", "foo..bar", false},
		{"empty", "", true},
		{"current directory", ".", true},
		{"parent directory", "..", true},
		{"forward slash", "tenant/cert", true},
		{"backslash", `tenant\cert`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCertName(tt.certName)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCertName(%q) error = %v, wantErr %v", tt.certName, err, tt.wantErr)
			}
		})
	}
}

func TestNormalizeCertDir(t *testing.T) {
	if got := normalizeCertDir(""); got != "." {
		t.Errorf("normalizeCertDir(\"\") = %q, want %q", got, ".")
	}
	if got := normalizeCertDir("/certs"); got != "/certs" {
		t.Errorf("normalizeCertDir(\"/certs\") = %q, want %q", got, "/certs")
	}
}

func TestCreatePrivateKeyPermissions(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer root.Close()

	if _, err := createPrivateKey(root, "cert.key"); err != nil {
		t.Fatalf("createPrivateKey: %v", err)
	}

	info, err := root.Stat("cert.key")
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Errorf("private key mode = %04o, want 0600", mode)
	}
}

func TestLoadOrCreatePrivateKeyRoundTrip(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer root.Close()

	created, err := loadOrCreatePrivateKey(root, "account.key")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	loaded, err := loadOrCreatePrivateKey(root, "account.key")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if !created.Equal(loaded) {
		t.Error("loaded key does not match the created one")
	}
}

func TestRootRejectsSymlinkEscape(t *testing.T) {
	parent := t.TempDir()
	certDir := filepath.Join(parent, "certs")
	if err := os.Mkdir(certDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	outside := filepath.Join(parent, "outside.crt")
	link := filepath.Join(certDir, "cert.crt")
	if err := os.Symlink(filepath.Join("..", "outside.crt"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	root, err := os.OpenRoot(certDir)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer root.Close()

	if err := root.WriteFile("cert.crt", []byte("certificate"), 0600); err == nil {
		t.Fatal("expected an error for a symlink escaping the certificate directory")
	}
	if _, err := os.Stat(outside); !os.IsNotExist(err) {
		t.Fatalf("outside file was created or stat returned an unexpected error: %v", err)
	}
}

func TestCreatePrivateKeyDoesNotTruncateExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.key")
	const original = "existing file"
	if err := os.WriteFile(path, []byte(original), 0644); err != nil {
		t.Fatalf("write existing file: %v", err)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer root.Close()

	if _, err := createPrivateKey(root, "cert.key"); err == nil {
		t.Fatal("expected exclusive private-key creation to fail")
	}
	data, err := root.ReadFile("cert.key")
	if err != nil {
		t.Fatalf("read existing file: %v", err)
	}
	if string(data) != original {
		t.Errorf("existing file was changed: got %q, want %q", data, original)
	}
}
