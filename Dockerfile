# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89
FROM golang:1.25-alpine@sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/snailmail ./cmd/snailmail
RUN CGO_ENABLED=0 go test -c -o /out/openpgp.test ./signer/openpgp

# Scanned here rather than on the runner: `go run tool@version` builds the tool
# with the ambient toolchain, so a runner older than go.mod's requirement cannot
# load these packages at all. The build image is digest-pinned and current.
FROM build AS vulncheck
RUN go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...

FROM debian@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS signing-test
COPY --from=build /out/openpgp.test /usr/local/bin/openpgp.test
RUN openpgp.test -test.run 'Test(Generate|Combined)'
RUN touch /signed-debian-passed

FROM build AS test
COPY --from=signing-test /signed-debian-passed /tmp/signed-debian-passed
RUN apk add --no-cache git gnupg python3 py3-pip
RUN go test ./...

FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce
RUN apk add --no-cache ca-certificates docker-cli git github-cli openssh-client python3 py3-pip
COPY --from=build /out/snailmail /usr/local/bin/snailmail
ENTRYPOINT ["snailmail"]
