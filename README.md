# snailmail

> relaxed package delivery

One tool to **create, host, sign and operate package repositories** of any
format — apt, dnf, apk, PyPI, npm, Helm, OCI, Cargo, Go, Maven, Nix, or plain
artifacts — on hosting you choose, and to **publish into repositories you
don't own** — AUR, Homebrew, nixpkgs, npmjs, PyPI, ghcr.

**Status: Phase 2 owned hosting, public S3 slice.** The current implementation
builds, structurally verifies, serves, and client-tests deterministic static
PyPI, Debian, and Helm repositories. Git-backed workspaces also support local
`init`, `setup`, `add`, `plan`, and `apply` workflows with immutable blobs,
reviewable plans, publication ledgers, and per-repository managed release
switching. Replacement of an existing managed release is currently implemented
only on Linux. Public PyPI repositories can additionally stage and publish to
S3-compatible object storage with immutable releases, conditional root-index
switching, checksum observation, and conditional restore. Private S3 reads,
shared remote blob storage, GitHub Pages, PR or approval gates, the public
status renderer, and containerized CI distribution are the remaining Phase 2
work. Signing, operational commands, and format breadth follow in Phase 3. See
[ARCHITECTURE.md](ARCHITECTURE.md) for the implementation contract and
[PLAN.md](PLAN.md) for the broader product design.

```sh
git init
go run ./cmd/snailmail init --name example
go run ./cmd/snailmail setup pypi --name python --output public/python
go run ./cmd/snailmail add python ./dist/*.whl
git add .gitignore snailmail.toml repos/python.lock.toml
git commit -m "configure Python repository"
go run ./cmd/snailmail plan
go run ./cmd/snailmail apply --plan snailmail.snailmail-plan.json
```

`plan` requires the manifest, configured locks, and existing publication
ledgers to be committed in a complete, non-shallow Git repository. `apply`
executes the reviewed plan without replanning, verifies staged repository
bytes, commits its exact publication ledger records with a compare-and-swap,
and publishes through the selected host's conditional release switch. S3 keeps
the verified tree under an immutable digest prefix and conditionally updates a
small root index that points clients at that tree.

Public S3-compatible PyPI setup uses the standard AWS credential chain; no
credential values are written to the manifest or plan:

```sh
go run ./cmd/snailmail setup pypi \
  --name python \
  --host s3 \
  --bucket example-packages \
  --prefix python \
  --region us-east-1 \
  --base-url https://packages.example.com/python
git add snailmail.toml repos/python.lock.toml docs/install-python.md
git commit -m "configure hosted Python repository"
go run ./cmd/snailmail plan
go run ./cmd/snailmail apply
```

The bucket or CDN must publicly serve the configured prefix, including
`.snailmail/stages/` during pre-publication verification. Use `--endpoint` and
`--use-path-style` for compatible object stores. `--visibility private` is
rejected until scoped client read credentials are implemented. Configure a
bucket lifecycle rule to expire abandoned `.snailmail/stages/` objects after a
grace period; immutable `.snailmail/releases/`, `.snailmail/manifests/`, and
`.snailmail/restores/` objects must not use that short-lived rule.

```sh
go run ./cmd/snailmail build pypi --input ./dist --output ./repository
go run ./cmd/snailmail verify pypi --repo ./repository
go run ./cmd/snailmail build deb --input ./dist --output ./apt-repository
go run ./cmd/snailmail verify deb --repo ./apt-repository
go run ./cmd/snailmail build helm --input ./dist --output ./helm-repository
go run ./cmd/snailmail verify helm --repo ./helm-repository
go run ./cmd/snailmail serve --repo ./repository
```

The short version:

- **Static-first.** Index generation is a pure function returning a file tree,
  so GitHub Pages, S3, or a USB stick are all valid hosting. The server is
  optional and never load-bearing.
- **Git is the state.** A repository's contents are a committed lockfile; the
  served index is a build artifact. Rollback is `git revert`.
- **Declarative.** One manifest says what should be published where; `plan` and
  `apply` reconcile against it.
- **Gated per repository.** The manifest carries the gate policy; the current
  local slice implements `auto`, while `pr` and `approval` remain future work.
- **Verified.** Apply verifies staged bytes structurally and, unless explicitly
  disabled, with the ecosystem client before switching the local target.
- **Local and S3.** `snailmail setup` records deterministic local targets or
  public S3-compatible PyPI targets. Key provisioning remains future work.

```
              apt      dnf      apk      aur      aur-bin  brew     nixpkgs
  ttysvg      0.1.2    0.1.2 ✗  0.1.2    0.1.2    0.1.2    0.1.2    0.0.7 ⚠
  exex        0.3.2    0.3.2 ✗  0.3.2    0.3.2    0.3.2    0.3.2    —
  cnvrt       0.0.3    0.0.3 ✗  0.0.3    0.0.3    0.0.3    0.0.3    —
  snailrace   0.0.5    0.0.5 ✗  0.0.5    0.0.5    PR #12   0.0.5    —

  ✗ verify failing   ⚠ lagging   PR # gate pending
```
