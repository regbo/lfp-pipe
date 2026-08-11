FROM golang:1.25.0-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/lfp-connect-auth ./cmd/lfp-connect-auth

FROM alpine:3.22
RUN addgroup -S lfp && adduser -S -G lfp lfp
COPY --from=build /out/lfp-connect-auth /usr/local/bin/lfp-connect-auth
USER lfp
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/lfp-connect-auth"]
