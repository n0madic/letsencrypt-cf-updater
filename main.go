package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/alexflint/go-arg"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
)

type args struct {
	AcmeURL  string   `arg:"-u,env:ACME_URL" placeholder:"URL" help:"ACME directory URL"`
	CertDir  string   `arg:"-D,env:ACME_CERT_DIR" placeholder:"PATH" help:"Directory to store the certificate"`
	CertName string   `arg:"-n,env:ACME_CERT_NAME" placeholder:"NAME" help:"Certificate name" default:"cert"`
	Domain   []string `arg:"-d,env:ACME_DOMAINS_REQUEST,separate" help:"List of domains. Multiple -d flags are allowed"`
	Email    string   `arg:"-m,env:ACME_ACCOUNT_EMAIL" help:"ACME account email"`
	Expire   int      `arg:"-e,env:ACME_CERT_EXPIRE" placeholder:"DAYS" help:"Certificate expiration in days for renew" default:"30"`
}

type Account struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	key          crypto.PrivateKey
}

func (u *Account) GetEmail() string {
	return u.Email
}

func (u Account) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *Account) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func main() {
	var args args
	arg.MustParse(&args)

	// Create a user. New accounts need an email and private key to start
	accountKey, err := loadOrCreatePrivateKey(filepath.Join(args.CertDir, "account.key"))
	if err != nil {
		log.Fatalf("Could not load or create private key: %v", err)
	}

	account := Account{
		Email: args.Email,
		key:   accountKey,
	}

	config := lego.NewConfig(&account)
	config.Certificate.KeyType = certcrypto.RSA2048
	if args.AcmeURL != "" {
		config.CADirURL = args.AcmeURL
	}

	accountPath := filepath.Join(args.CertDir, "account.json")
	_, err = os.Stat(accountPath)
	if os.IsNotExist(err) {
		client, err := lego.NewClient(config)
		if err != nil {
			log.Fatalf("Could not create ACME client for registration: %v", err)
		}

		// New users will need to register
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			log.Fatalf("Could not register user: %v", err)
		}
		account.Registration = reg

		// Save user
		data, err := json.MarshalIndent(account, "", "\t")
		if err != nil {
			log.Fatalf("Could not marshal user: %v", err)
		}
		err = os.WriteFile(accountPath, data, 0600)
		if err != nil {
			log.Fatalf("Could not save user: %v", err)
		}
	} else if err == nil {
		// Load user
		data, err := os.ReadFile(accountPath)
		if err != nil {
			log.Fatalf("Could not read user: %v", err)
		}
		err = json.Unmarshal(data, &account)
		if err != nil {
			log.Fatalf("Could not load user: %v", err)
		}
		account.key = accountKey
	} else {
		log.Fatalf("Could not stat user config: %v", err)
	}

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatalf("Could not create ACME client: %v", err)
	}

	// Enable DNS challenge provider
	provider, err := cloudflare.NewDNSProvider()
	if err != nil {
		log.Fatalf("Could not create DNS provider: %v", err)
	}
	// Set DNS challenge provider
	err = client.Challenge.SetDNS01Provider(provider)
	if err != nil {
		log.Fatalf("Could not set DNS challenge provider: %v", err)
	}

	domains := args.Domain
	renew := false
	certPath := filepath.Join(args.CertDir, args.CertName+".crt")
	_, err = os.Stat(certPath)
	// if certificate exists, check if it needs to be renewed
	if err == nil {
		// Load the certificate
		data, err := os.ReadFile(certPath)
		if err != nil {
			log.Fatalf("Could not read certificate: %v", err)
		}
		// Parse the certificate
		certResource, err := certcrypto.ParsePEMCertificate(data)
		if err != nil {
			log.Fatalf("Could not parse certificate: %v", err)
		}
		// Extract domains from certificate
		domains = certcrypto.ExtractDomains(certResource)
		// Check if domains match
		if len(args.Domain) > 0 && !slicesEqual(domains, args.Domain) {
			renew = true
			domains = args.Domain
			log.Infof("Domains do not match, renewal is necessary")
		}
		// Renew the certificate if necessary
		if time.Until(certResource.NotAfter) < time.Duration(args.Expire)*24*time.Hour {
			renew = true
			log.Infof("Certificate will expire in %d days, renewal is necessary", int(time.Until(certResource.NotAfter).Hours()/24))
		}
	}
	// Obtain or renew a certificate
	if renew || os.IsNotExist(err) {
		if len(domains) == 0 {
			log.Fatalf("No domains specified")
		}
		privateKey, err := loadOrCreatePrivateKey(filepath.Join(args.CertDir, args.CertName+".key"))
		if err != nil {
			log.Fatalf("Could not load or create private key: %v", err)
		}
		// Obtain a certificate for the domain
		request := certificate.ObtainRequest{
			Domains:    domains,
			Bundle:     false,
			PrivateKey: privateKey,
		}

		certResource, err := client.Certificate.Obtain(request)
		if err != nil {
			log.Fatalf("Could not obtain certificate: %v", err)
		}

		// Save the certificate
		err = os.WriteFile(certPath, certResource.Certificate, 0600)
		if err != nil {
			log.Fatalf("Could not save certificate: %v", err)
		}
		log.Infof("Certificate obtained for %s and saved to %s", domains, certPath)
	} else {
		log.Infof("Certificate for %s is still valid", domains)
	}
}

func loadOrCreatePrivateKey(path string) (*rsa.PrivateKey, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return createPrivateKey(path)
	}

	return loadPrivateKey(path)
}

func createPrivateKey(path string) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	file, err := os.Create(path)
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

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("invalid private key")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sort.Strings(a)
	sort.Strings(b)
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
