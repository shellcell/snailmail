# Third-party licences

snailmail is MIT licensed. It links the modules below, all under permissive
licences compatible with redistribution: no dependency is copyleft, and none
imposes a condition beyond attribution.

Recorded here so an adopter does not have to repeat the audit. Regenerate with:

```sh
go list -deps -f '{{with .Module}}{{.Path}} {{.Dir}}{{end}}' ./...
```

and read the licence file at each module root.

## Apache-2.0

The AWS SDK for Go v2 and its supporting modules, used only by the S3 blob store
and host adapters — both compiled out by the `nos3` build tag.

- `github.com/aws/aws-sdk-go-v2` and its `config`, `credentials`,
  `feature/ec2/imds`, `service/s3`, `service/sso`, `service/ssooidc`,
  `service/sts` and internal modules
- `github.com/aws/smithy-go`

## BSD-3-Clause

- `github.com/ProtonMail/go-crypto` — OpenPGP signing and verification
- `github.com/cloudflare/circl` — cryptographic primitives used by the above
- `github.com/klauspost/compress` — deterministic gzip and zstd
- `github.com/ulikunitz/xz` — xz, for Debian control archives
- `golang.org/x/crypto`, `golang.org/x/net`, `golang.org/x/sys`

## MIT

- `github.com/Masterminds/semver/v3` — Helm chart version ordering
- `github.com/pelletier/go-toml/v2` — manifest and lock encoding
- `gopkg.in/yaml.v3` — Helm index encoding

## Tools

`github.com/goreleaser/nfpm/v2` builds the deb, rpm and apk packages during
`make packages`. It is run with `go run` at release time and is not linked into
the binary, so it is not a dependency of the distributed artifact.
