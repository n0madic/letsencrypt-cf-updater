package main

import (
	"os"
	"path/filepath"
	"testing"
)

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
