FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY . .
RUN go build -o /build/api ./cmd/api

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /build/api /usr/local/bin/api
COPY configs /etc/nhiid/configs
COPY migrations /etc/nhiid/migrations
EXPOSE 8080
CMD ["api"]
