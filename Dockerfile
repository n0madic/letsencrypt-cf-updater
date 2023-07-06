FROM golang:alpine AS builder

WORKDIR /src

COPY go.* ./

RUN go mod download

COPY *.go ./

RUN go install -ldflags="-s -w"


FROM alpine:latest

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /go/bin/* /bin/

WORKDIR /certs

ENTRYPOINT ["/bin/letsencrypt-cf-updater"]
