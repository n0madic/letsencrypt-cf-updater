FROM golang:alpine AS builder

WORKDIR /src

COPY go.* ./

RUN go mod download

COPY *.go ./

RUN go install -ldflags="-s -w"


FROM alpine:latest

RUN apk add --quite --no-cache ca-certificates git

COPY --from=builder /go/bin/* /bin/

WORKDIR /certs
