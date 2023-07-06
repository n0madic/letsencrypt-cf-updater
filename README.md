# letsencrypt-cf-updater

This is a simple utility to update LetsEncrypt certificates via Cloudflare DNS.

## Install

```
go install github.com/n0madic/letsencrypt-cf-updater@latest
```

Or run docker image:

```
docker run --rm -it -v /path/to/certs:/certs -e CLOUDFLARE_DNS_API_TOKEN n0madic/letsencrypt-cf-updater
```

## Usage

Set Cloudflare API credentials to `CLOUDFLARE_EMAIL`, `CLOUDFLARE_API_KEY` or `CLOUDFLARE_DNS_API_TOKEN` or `CLOUDFLARE_ZONE_API_TOKEN` environment variables.

```
Usage: letsencrypt-cf-updater [--acmeurl URL] [--certdir PATH] [--certname NAME] [--domain DOMAIN] [--email EMAIL] [--expire DAYS]

Options:
  --acmeurl URL, -u URL
                         ACME directory URL [env: ACME_URL]
  --certdir PATH, -D PATH
                         Directory to store the certificate [env: ACME_CERT_DIR]
  --certname NAME, -n NAME
                         Certificate name [default: cert, env: ACME_CERT_NAME]
  --domain DOMAIN, -d DOMAIN
                         List of domains [env: ACME_DOMAINS_REQUEST]
  --email EMAIL, -m EMAIL
                         ACME account email [env: ACME_ACCOUNT_EMAIL]
  --expire DAYS, -e DAYS
                         Certificate expiration in days for renew [default: 30, env: ACME_CERT_EXPIRE]
  --help, -h             display this help and exit
```
