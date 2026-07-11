# Single image that contains all NHIID binaries (api, worker, collector, migrate).
# Services in docker-compose select which one to run via `command:`.
FROM golang:1.26-alpine AS build
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/ ./cmd/...

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 nhiid
WORKDIR /app
COPY --from=build /out/ /usr/local/bin/
# config + risk weights + demo fixtures are read at runtime relative to WORKDIR
COPY configs ./configs
COPY fixtures ./fixtures
USER nhiid
EXPOSE 8080 9090
CMD ["api"]
