package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/alexflint/go-arg"
	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/log"
	"github.com/go-acme/lego/v5/providers/dns/cloudflare"
	"github.com/go-acme/lego/v5/registration"
)

type args struct {
	AcmeURL  string   `arg:"-u,env:ACME_URL" placeholder:"URL" help:"ACME directory URL"`
	Bundle   bool     `arg:"-b,env:ACME_CERT_BUNDLE" help:"Append the issuer certificate chain to the certificate"`
	CertDir  string   `arg:"-D,env:ACME_CERT_DIR" placeholder:"PATH" help:"Directory to store the certificate"`
	CertName string   `arg:"-n,env:ACME_CERT_NAME" placeholder:"NAME" help:"Certificate name" default:"cert"`
	Domain   []string `arg:"-d,env:ACME_DOMAINS_REQUEST,separate" help:"List of domains. Multiple -d flags are allowed"`
	Email    string   `arg:"-m,env:ACME_ACCOUNT_EMAIL" help:"ACME account email"`
	Expire   int      `arg:"-e,env:ACME_CERT_EXPIRE" placeholder:"DAYS" help:"Certificate expiration in days for renew" default:"30"`
}

type Account struct {
	Email        string                `json:"email"`
	Registration *acme.ExtendedAccount `json:"registration"`
	key          crypto.Signer
}

func (u *Account) GetEmail() string {
	return u.Email
}

func (u Account) GetRegistration() *acme.ExtendedAccount {
	return u.Registration
}

func (u *Account) GetPrivateKey() crypto.Signer {
	return u.key
}

// legacyAccount is the account file layout written by lego v4, where the
// registration was stored as {"body": ..., "uri": ...} instead of an
// acme.ExtendedAccount.
type legacyAccount struct {
	Registration *struct {
		Body acme.Account `json:"body"`
		URI  string       `json:"uri"`
	} `json:"registration"`
}

func main() {
	var args args
	arg.MustParse(&args)

	if err := validateCertName(args.CertName); err != nil {
		log.Fatal("Invalid certificate name", log.ErrorAttr(err))
	}

	certDir := normalizeCertDir(args.CertDir)
	certRoot, err := os.OpenRoot(certDir)
	if err != nil {
		log.Fatal("Could not open certificate directory", log.ErrorAttr(err))
	}
	defer certRoot.Close()

	ctx := context.Background()

	// Create a user. New accounts need an email and private key to start
	accountKey, err := loadOrCreatePrivateKey(certRoot, "account.key")
	if err != nil {
		log.Fatal("Could not load or create private key", log.ErrorAttr(err))
	}

	account := Account{
		Email: args.Email,
		key:   accountKey,
	}

	config := lego.NewConfig(&account)
	if args.AcmeURL != "" {
		config.CADirURL = args.AcmeURL
	}

	const accountPath = "account.json"
	_, err = certRoot.Stat(accountPath)
	if os.IsNotExist(err) {
		client, err := lego.NewClient(config)
		if err != nil {
			log.Fatal("Could not create ACME client for registration", log.ErrorAttr(err))
		}

		// New users will need to register
		reg, err := client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			log.Fatal("Could not register user", log.ErrorAttr(err))
		}
		account.Registration = reg

		// Save user
		if err := saveAccount(certRoot, accountPath, &account); err != nil {
			log.Fatal("Could not save user", log.ErrorAttr(err))
		}
	} else if err == nil {
		// Load user
		data, err := certRoot.ReadFile(accountPath)
		if err != nil {
			log.Fatal("Could not read user", log.ErrorAttr(err))
		}
		err = json.Unmarshal(data, &account)
		if err != nil {
			log.Fatal("Could not load user", log.ErrorAttr(err))
		}
		// Account files written by lego v4 store the registration in a
		// different layout, convert them instead of losing the account URL
		if account.Registration == nil || account.Registration.Location == "" {
			if err := migrateLegacyAccount(data, &account); err != nil {
				log.Fatal("Could not migrate user", log.ErrorAttr(err))
			}
			if err := saveAccount(certRoot, accountPath, &account); err != nil {
				log.Fatal("Could not save migrated user", log.ErrorAttr(err))
			}
			log.Info("Account registration migrated to the current format")
		}
		// Command line arguments and environment variables take precedence
		// over the values stored in the account file
		if args.Email != "" && args.Email != account.Email {
			log.Info("Account email overridden",
				slog.String("old", account.Email), slog.String("new", args.Email))
			account.Email = args.Email
		}
		account.key = accountKey
	} else {
		log.Fatal("Could not stat user config", log.ErrorAttr(err))
	}

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal("Could not create ACME client", log.ErrorAttr(err))
	}

	// Enable DNS challenge provider
	provider, err := cloudflare.NewDNSProvider()
	if err != nil {
		log.Fatal("Could not create DNS provider", log.ErrorAttr(err))
	}
	// Set DNS challenge provider
	err = client.Challenge.SetDNS01Provider(provider)
	if err != nil {
		log.Fatal("Could not set DNS challenge provider", log.ErrorAttr(err))
	}

	domains := args.Domain
	renew := false
	certName := args.CertName + ".crt"
	certPath := filepath.Join(certDir, certName)
	_, err = certRoot.Stat(certName)
	if err != nil && !os.IsNotExist(err) {
		log.Fatal("Could not stat certificate", log.ErrorAttr(err))
	}
	certExists := err == nil
	// if certificate exists, check if it needs to be renewed
	if certExists {
		// Load the certificate
		data, err := certRoot.ReadFile(certName)
		if err != nil {
			log.Fatal("Could not read certificate", log.ErrorAttr(err))
		}
		// Parse the certificate
		certResource, err := certcrypto.ParsePEMCertificate(data)
		if err != nil {
			log.Fatal("Could not parse certificate", log.ErrorAttr(err))
		}
		// Extract domains from certificate
		domains = certcrypto.ExtractDomains(certResource)
		// Check if domains match
		if len(args.Domain) > 0 && !slicesEqual(domains, args.Domain) {
			renew = true
			domains = args.Domain
			log.Info("Domains do not match, renewal is necessary", log.DomainsAttr(domains))
		}
		// Renew the certificate if necessary
		if time.Until(certResource.NotAfter) < time.Duration(args.Expire)*24*time.Hour {
			renew = true
			log.Info("Certificate is about to expire, renewal is necessary",
				slog.Int("days", int(time.Until(certResource.NotAfter).Hours()/24)))
		}
	}
	// Obtain or renew a certificate
	if renew || !certExists {
		if len(domains) == 0 {
			log.Fatal("No domains specified")
		}
		privateKey, err := loadOrCreatePrivateKey(certRoot, args.CertName+".key")
		if err != nil {
			log.Fatal("Could not load or create private key", log.ErrorAttr(err))
		}
		// Obtain a certificate for the domain
		request := certificate.ObtainRequest{
			Domains:    domains,
			Bundle:     args.Bundle,
			PrivateKey: privateKey,
			KeyType:    certcrypto.RSA2048,
		}

		certResource, err := client.Certificate.Obtain(ctx, request)
		if err != nil {
			log.Fatal("Could not obtain certificate", log.ErrorAttr(err))
		}

		// Save the certificate
		err = certRoot.WriteFile(certName, certResource.Certificate, 0600)
		if err != nil {
			log.Fatal("Could not save certificate", log.ErrorAttr(err))
		}
		log.Info("Certificate obtained", log.DomainsAttr(domains), slog.String("path", certPath))
	} else {
		log.Info("Certificate is still valid", log.DomainsAttr(domains))
	}
}

func validateCertName(name string) error {
	switch {
	case name == "":
		return errors.New("certificate name must not be empty")
	case name == "." || name == "..":
		return errors.New("certificate name cannot be a dot path element")
	case strings.ContainsAny(name, `/\`):
		return errors.New("certificate name must not contain path separators")
	default:
		return nil
	}
}

func normalizeCertDir(dir string) string {
	if dir == "" {
		return "."
	}
	return dir
}

func saveAccount(root *os.Root, path string, account *Account) error {
	data, err := json.MarshalIndent(account, "", "\t")
	if err != nil {
		return err
	}

	return root.WriteFile(path, data, 0600)
}

func migrateLegacyAccount(data []byte, account *Account) error {
	var legacy legacyAccount
	if err := json.Unmarshal(data, &legacy); err != nil {
		return err
	}
	if legacy.Registration == nil || legacy.Registration.URI == "" {
		return errors.New("account file has no registration URL")
	}

	account.Registration = &acme.ExtendedAccount{
		Account:  legacy.Registration.Body,
		Location: legacy.Registration.URI,
	}

	return nil
}

func loadOrCreatePrivateKey(root *os.Root, path string) (*rsa.PrivateKey, error) {
	if _, err := root.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return createPrivateKey(root, path)
		}
		return nil, err
	}

	return loadPrivateKey(root, path)
}

func createPrivateKey(root *os.Root, path string) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	file, err := root.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	err = pem.Encode(file, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err != nil {
		return nil, err
	}

	return key, nil
}

func loadPrivateKey(root *os.Root, path string) (*rsa.PrivateKey, error) {
	data, err := root.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("invalid private key")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// slicesEqual reports whether both slices contain the same set of strings,
// regardless of order. The arguments are left untouched: the caller relies on
// the original order of the domains.
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sortedA := append([]string(nil), a...)
	sortedB := append([]string(nil), b...)
	sort.Strings(sortedA)
	sort.Strings(sortedB)
	for i, v := range sortedA {
		if v != sortedB[i] {
			return false
		}
	}
	return true
}
