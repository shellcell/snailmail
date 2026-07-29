# snailmail

> relaxed package delivery

One tool to **create, host, sign and operate package repositories** of any
format — apt, dnf, apk, PyPI, npm, Helm, OCI, Cargo, Go, Maven, Nix, or plain
artifacts — on hosting you choose, and to **publish into repositories you
don't own** — AUR, Homebrew, nixpkgs, npmjs, PyPI, ghcr.

**Status: Phase 2 complete; Phase 3 signing foundation implemented.** The current implementation
builds, structurally verifies, serves, and client-tests deterministic static
PyPI, Debian, Helm, RPM and Alpine repositories, and publishes `raw`
repositories of artifacts that carry no ecosystem metadata. Each format's
client-test is the real client: pip, apt, helm, dnf and apk installing from the
built tree in a container. Debian, RPM and Alpine repositories are signed, each
with the scheme its clients verify. Git-backed workspaces also support local
`init`, `setup`, `add`, `plan`, and `apply` workflows with immutable blobs,
reviewable plans, publication ledgers, and per-repository managed release
switching. Replacement of an existing managed release needs an atomic
directory-entry exchange, so it is implemented on Linux and macOS; creating a
first release is portable. PyPI repositories can additionally stage and publish to
S3-compatible object storage with immutable releases, conditional root-index
switching, checksum observation, conditional restore, and optional scoped
private reads. Shared S3 blob storage, public GitHub Pages with a companion
preview site, `auto`/`pr`/signed-`approval` gates, deterministic public status
artifacts, and a containerized GitHub Actions workflow complete Phase 2.
Phase 3 now includes encrypted local RSA4096 OpenPGP keys, a versioned signing
compatibility table, `keys new|publish|audit|rotate`, explicit plan-resolved signer
effects, authenticated Debian `InRelease`/`Release.gpg` output, receipt-backed
Debian key rotation, and placement-level `promote`/`yank`. Additional key
backends, operational commands, and format breadth remain Phase 3 work. See
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

Promotions and yanks edit only placement records. Package versions, blob
bindings, and publication history remain available for later re-promotion:

```sh
go run ./cmd/snailmail promote --track testing python snail-demo 1.2.3
go run ./cmd/snailmail yank --track stable python snail-demo 1.2.3
# Or remove every placement for the exact version:
go run ./cmd/snailmail yank --all python snail-demo 1.2.3

git diff -- repos/python.lock.toml
git add repos/python.lock.toml
git commit -m "update Python package placements"
go run ./cmd/snailmail plan
go run ./cmd/snailmail apply
```

The repository and package version are exact; promotion does not copy package
versions between repositories. Each repository renders only its configured
`--track` (default `stable`), and Debian additionally renders only placements for
its configured suite. Other placements remain recorded but are not exposed in
that view. Removing the final visible placement publishes a valid empty index
while retaining immutable package and blob records in Git. Debian defaults a
new placement's distro to the configured suite; `--distro DISTRO` selects another
distro coordinate explicitly.

Retention pruning removes only older placements, independently per package,
track, and distro, using native PEP 440, Debian, or SemVer precedence:

```sh
go run ./cmd/snailmail prune python --keep 5
git add repos/python.lock.toml
git commit -m "prune old Python placements"
go run ./cmd/snailmail plan
go run ./cmd/snailmail apply
```

Versions tied at the retention boundary are kept together. Prune does not remove
package-version records, CAS objects, remote blobs, or publication history;
physical blob GC remains a separate future operation with tombstones and a grace
period.

`snailmail check` is a read-only integrity audit of every retained package
version, including yanked and pruned versions. It verifies local CAS bytes or
fetches the configured S3 authority into temporary storage, reparses native
package facts, and revalidates historical publication bindings. Upstream release
discovery remains unavailable until releases are modeled. `check --origins`
re-fetches explicitly adopted URLs and compares their pinned bytes; default
checks remain offline from external sources. Origin checks process at most four
sorted records per run; `--origin-offset` selects subsequent batches.

`snailmail adopt --sha256 HEX --public-origin REPOSITORY URL` records one
explicitly selected artifact in an existing owned repository. The lowercase
SHA-256 pin is mandatory; `--public-origin` confirms that the complete requested
URL is non-secret and may be committed and printed. Lock schema 2 retains that
URL, plans display every visible adopted acquisition, and `--dry-run` validates
up to 128 MiB without changing CAS or lock state. Adoption currently requires
the local blob store and does not claim authorship, build provenance, source
signatures, or historical snailmail publication.

`snailmail status` reports committed workspace evidence without contacting
hosts or providers. Human output summarizes visible and retained versions,
visible publication-binding completeness, and whether a managed deployment
receipt is recorded; `--json` emits the same deterministic schema for
automation. A receipt is evidence of a prior successful apply, not proof that a
host currently serves those bytes.

`snailmail doctor URL` needs no workspace and inspects a public HTTPS PyPI,
Debian, or Helm repository. It parses bounded native indexes, follows at most the
configured artifact limit, and checks referenced availability, size, SHA-256,
archive validity, and package identity. Use `--project` for PyPI artifacts and
`--suite` for a Debian base URL. Debian Release signatures and Helm provenance
are explicitly reported as unverified in this initial slice. Runs inspect at
most four artifacts, cap each expanded archive at 64 MiB, and stop after two
minutes.

`raw` repositories publish artifacts that carry no ecosystem metadata: release
tarballs, static binaries, installers. Every other format reads a package name
and version out of the bytes; raw cannot, so identity comes from the filename by
convention, or from you when the convention does not apply.

```sh
go run ./cmd/snailmail setup raw --name tools --output public/tools

# <name>_<version>[_<os>][_<arch>].<ext> is read without flags.
go run ./cmd/snailmail add tools ./dist/ttysvg_0.1.2_linux_amd64.tar.gz

# Anything else needs identity supplied, including a name with an underscore,
# which cannot be told apart from an extra field.
go run ./cmd/snailmail add --name ttysvg --version 0.2.0 tools ./dist/build-final.bin

go run ./cmd/snailmail plan && go run ./cmd/snailmail apply
go run ./cmd/snailmail verify raw --repo public/tools
```

Artifacts are published at `<name>/<version>/<filename>` beside a generated
`SHA256SUMS` and `index.html`. Identity lives in the path on purpose: because
it may have come from a flag rather than from the bytes, the published tree has
to record it somewhere a later reader can check without knowing what was typed.
`SHA256SUMS` is the interchange format — `sha256sum -c` verifies a raw
repository with no snailmail present. Raw has no signing: it is not an
ecosystem, so no client knows to check a signature.

Signed Debian repositories use an encrypted private key outside the workspace
and commit only canonical public forms. Set a passphrase through the environment
(never an argument), generate the key, and reference it during setup:

```sh
export SNAILMAIL_KEY_PASSPHRASE='use-a-secret-manager-value'
go run ./cmd/snailmail keys new archive-signing --expires-in 17520h
go run ./cmd/snailmail setup deb \
  --name debian \
  --output public/debian \
  --suite stable \
  --architectures amd64 \
  --signing-key archive-signing
go run ./cmd/snailmail keys audit
git add snailmail.toml keys/ repos/debian.lock.toml
git commit -m "configure signed Debian repository"
go run ./cmd/snailmail plan
go run ./cmd/snailmail apply
```

The file backend stores encrypted private keys under
`$XDG_DATA_HOME/snailmail/private-keys` (or
`~/.local/share/snailmail/private-keys`) with mode `0600`. Passphrases must
contain at least 24 bytes and should come from a secret manager. In a container,
prefer `SNAILMAIL_KEY_PASSPHRASE_FILE` pointing at a mounted file: a container's
environment stays readable through the runtime's inspection API for as long as
the container exists, whereas a file can be read once and removed. Setting both
variables is rejected rather than resolved silently. `keys publish`
recreates missing public forms after validating the private identity. Planning
compiles content-addressed `InRelease` and `Release.gpg` signing nodes over the
exact Debian `Release` bytes, signs each node twice to prove deterministic
backend behavior, verifies both signatures, and embeds only public node
responses in the reviewed plan. Apply does not load the private key. Signed
client verification uses apt's `signed-by`; migrated unsigned Debian
repositories remain readable but `keys audit` reports them as errors. New
unsigned Debian setup requires the explicit `--allow-unsigned` compatibility
opt-out.

Debian rotation keeps one active `InRelease` signer and a stable binary keyring.
Introduction publishes both identities while the old key continues signing;
activation switches to the successor only after the introducing deployment
receipt has aged through the minimum refresh window; retirement removes old
trust only after a second deployed overlap window:

```sh
go run ./cmd/snailmail keys rotate debian \
  --successor archive-signing-2027 \
  --minimum-refresh 720h
git add snailmail.toml keys/
git commit -m "introduce successor archive key"
go run ./cmd/snailmail plan && go run ./cmd/snailmail apply

# After `keys audit` reports the introducing state ready:
go run ./cmd/snailmail keys rotate debian --advance --yes
git add snailmail.toml && git commit -m "activate successor archive key"
go run ./cmd/snailmail plan && go run ./cmd/snailmail apply

# After the activated overlap is ready:
go run ./cmd/snailmail keys rotate debian --advance --yes
git add snailmail.toml && git commit -m "retire old archive key"
go run ./cmd/snailmail plan && go run ./cmd/snailmail apply
```

The minimum window is seven days. Its clock starts from the canonical
post-verification deployment receipt, not from the manifest edit or plan time.
Repository-hosted keyrings do not update clients automatically: refresh the
local `/usr/share/keyrings` file through configuration management or a keyring
package before activation. In CI, replace `SNAILMAIL_SIGNING_KEY_REF` and its
encrypted private-key secret with the successor before planning the activated
state; apply still receives no private key.

`plan` requires the manifest, configured locks, publication ledgers, and
deployment receipts to be committed in a complete, non-shallow Git repository. `apply`
executes the reviewed plan without replanning, verifies staged repository
bytes, commits its exact publication ledger records with a compare-and-swap,
and publishes through the selected host's conditional release switch. After
canonical verification succeeds, apply commits a deployment receipt separately
from the pre-effect publication ledger. S3 keeps
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

The bucket or gateway must serve the configured prefix, including
`.snailmail/stages/` during pre-publication verification. Use `--endpoint` and
`--use-path-style` for compatible object stores. All non-loopback S3 API and
package client endpoints must use HTTPS. Configure a
bucket lifecycle rule to expire abandoned `.snailmail/stages/` objects after a
grace period; immutable `.snailmail/releases/`, `.snailmail/manifests/`, and
`.snailmail/restores/` objects must not use that short-lived rule.

Private S3-compatible PyPI uses a Basic-auth gateway and a short-lived
credential broker. The broker is a compiled executable selected at runtime by
`SNAILMAIL_CREDENTIAL_BROKER`; set `--visibility private --read-auth basic
--credential-broker default` during setup. Snailmail sends the reviewed
workspace, host, plan, change, tree, and object-prefix scope as JSON on stdin.
The helper returns `username`, `password`, and RFC3339 `expires_at` JSON, with a
maximum lifetime of 15 minutes. The helper and gateway are trusted to enforce
the supplied scope. The helper receives only selected profile, web-identity,
TLS, and `SNAILMAIL_BROKER_*` environment variables, not the complete snailmail
environment. Credentials stay out of Git, plans, URLs, and argv; pip receives
them through an isolated temporary netrc that is destroyed after verification.

Shared S3 blob storage keeps Git locks provider-neutral while treating the
local CAS as a verified disposable cache:

```sh
go run ./cmd/snailmail blob-store s3 \
  --bucket example-artifacts \
  --prefix snailmail/cas \
  --region us-east-1
```

Public GitHub Pages requires distinct pre-provisioned production and preview
sites that deploy the root of the configured branch. Authenticate `gh`, then:

```sh
go run ./cmd/snailmail setup pypi \
  --name python \
  --host github-pages \
  --github-repo example/packages \
  --github-preview-repo example/packages-preview \
  --base-url https://example.github.io/packages \
  --preview-url https://example.github.io/packages-preview
```

Pages publication uses exact orphan commits, immutable stage and restore refs,
force-with-lease compare-and-swap, `.nojekyll`, and bounded propagation polling.
Private Pages repositories are rejected.

For a PR gate, initialize the workspace with its reviewed state repository and
configure `--gate pr`. Apply verifies that the exact Git revision was merged by
a PR and remains reachable from that repository's default branch.

```sh
go run ./cmd/snailmail init --name example --forge-repo example/state
```

Approval gates use Ed25519 evidence. Keep the generated private key outside the
workspace; commit only the printed public key in repository configuration:

```sh
go run ./cmd/snailmail approval-key generate --out ../snailmail-approval-key.json
go run ./cmd/snailmail setup pypi --name python --output public/python \
  --gate approval --approval-keys BASE64_PUBLIC_KEY
go run ./cmd/snailmail plan
go run ./cmd/snailmail approve --repository python \
  --key ../snailmail-approval-key.json --yes
go run ./cmd/snailmail apply
```

`approve` signs the exact plan ID, repository, key identity, and expiry. Apply
reauthorizes before every stage, commit, and compensating restore.

Render the read-only public matrix and machine-readable status from committed
locks, ledgers, deployment receipts, and an optional current plan:

```sh
go run ./cmd/snailmail render --output site
```

`plan` and `apply` build and stage under `.snailmail/stage` in the workspace
rather than in `TMPDIR`, so artifacts hard-link from the local CAS instead of
being copied and large trees are never held in a `tmpfs`. Set an absolute
`SNAILMAIL_STAGE_DIR` to stage elsewhere.

The AWS SDK is the largest single component of the binary. Builds that only
target local directories or GitHub Pages can exclude it:

```sh
go build -trimpath -ldflags="-s -w" -tags nos3 ./cmd/snailmail
```

That drops the stripped binary from about 20.6 MB to 12.8 MB. S3 hosts and S3
blob stores then report that the build has no S3 support; every other format,
host, and command is unaffected. The default build keeps S3.

`Dockerfile` builds the runtime image. `examples/github-actions.yml` is a pinned
workflow template to copy into your own workspace repository, with read-only PR
testing and a protected default-branch apply job; this repository is not itself
a snailmail workspace yet, so the template is linted here rather than run. Configure `AWS_ROLE_ARN`/`AWS_REGION` repository variables for OIDC-backed
S3 access. Cross-repository Pages writes need `SNAILMAIL_GITHUB_TOKEN`. Approval
jobs need `SNAILMAIL_APPROVAL_REPOSITORIES` and the
`SNAILMAIL_APPROVAL_PRIVATE_KEY` secret. Private S3 requires an organization
image containing its compiled broker plus the corresponding runtime variables.
Signed Debian planning additionally uses `SNAILMAIL_SIGNING_KEY_REF` as the
non-secret `<workspace-id>/<key-name>` repository variable and the
`SNAILMAIL_SIGNING_PRIVATE_KEY` and `SNAILMAIL_KEY_PASSPHRASE` secrets. The
workflow materializes that encrypted key only in runner temporary storage and
does not pass it to apply.

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
- **Scriptable.** Every command that reports a result accepts `--json`, so CI
  is the CLI in a container.
- **Gated per repository.** `auto`, provider-bound merged-PR evidence, and
  plan-bound Ed25519 approval evidence share the same apply graph.
- **Verified.** Apply verifies staged bytes structurally and, unless explicitly
  disabled, with the ecosystem client before switching the local target.
- **Local, S3, and Pages.** `snailmail setup` records deterministic local
  targets, public/private S3-compatible PyPI, or public GitHub Pages PyPI with a
  separate preview site.
- **Plan-resolved signing.** Debian signing keys remain outside Git; exact
  verified `InRelease` and `Release.gpg` responses are reviewed in the plan and
  replayed without signer access during apply.

```
              apt      dnf      apk      aur      aur-bin  brew     nixpkgs
  ttysvg      0.1.2    0.1.2 ✗  0.1.2    0.1.2    0.1.2    0.1.2    0.0.7 ⚠
  exex        0.3.2    0.3.2 ✗  0.3.2    0.3.2    0.3.2    0.3.2    —
  cnvrt       0.0.3    0.0.3 ✗  0.0.3    0.0.3    0.0.3    0.0.3    —
  snailrace   0.0.5    0.0.5 ✗  0.0.5    0.0.5    PR #12   0.0.5    —

  ✗ verify failing   ⚠ lagging   PR # gate pending
```
