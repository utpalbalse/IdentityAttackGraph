FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY . .
RUN go build -o /build/worker ./cmd/worker

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /build/worker /usr/local/bin/worker
COPY configs /etc/nhiid/configs
COPY migrations /etc/nhiid/migrations
CMD ["worker"]
