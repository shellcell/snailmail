# snailmail

> relaxed package delivery

One tool to **create, host, sign and operate package repositories** from a
git-backed workspace. Builds are deterministic, plans are reviewable, artifacts
are immutable, and before anything is published a real client — `pip`, `apt`,
`dnf`, `apk`, `helm` — installs from the built tree in a container.

MIT licensed. See [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md).

**Six formats today.** Debian (`apt`), RPM (`dnf`/`yum`), Alpine (`apk`), PyPI
(`pip`), Helm, and `raw` for artifacts that carry no ecosystem metadata. Debian,
RPM, Alpine and Helm are signed with the scheme their own clients verify.

**Three hosts today.** A local directory, GitHub Pages, and S3-compatible object
storage — though not every format on every host; see the table below.

**Planned, not built:** npm, OCI, Cargo, Go, Maven and Nix repositories, and
publishing into registries you do not own (AUR, Homebrew, nixpkgs, npmjs, PyPI,
ghcr). [PLAN.md](PLAN.md) has the design; none of it works yet.

## Quickstart

From an empty directory to a published PyPI repository:

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

`plan` writes what it intends to do; `apply` does it and records a publication
ledger entry. Nothing reaches a host until a plan has been applied.

Each command prints the one that usually comes next, so the sequence can be
followed without this page. The `git commit` in the middle is not incidental:
desired state is reviewed as a diff, and `plan` reads committed state only.

`apply` reports each phase as it runs — a publication takes minutes, most of it
building and running a real client per format — and writes that narration to
stderr, so `--json` still emits exactly one document on stdout.

`apply --dry-run` builds, verifies and checks every gate, then stops before
writing anything to a host. It is not the same as `--structural-only`, which only
skips client verification and still publishes.

Every command that takes `--workspace` also accepts `--root`.

## What runs where

| Host | pypi | deb | rpm | apk | helm | raw |
|---|---|---|---|---|---|---|
| local directory | yes | yes | yes | yes | yes | yes |
| GitHub Pages | yes | yes | yes | yes | yes | yes |
| S3 / R2 / GCS | yes | — | unsigned only | — | yes | yes |

An object store makes a revision live by writing one object, so it can serve a
format only where a single path switches. Debian needs a `Release` and its detached
signature to become live together; Alpine has one index per architecture; and a
*signed* yum repository has to switch `repomd.xml` with the `repomd.xml.asc` that
signs it. Those are structural limits, not missing work — a local directory or
GitHub Pages commits a whole tree at once and serves all six.

One caveat for object storage: the browsable `index.html` is generated fresh for
every revision, so it is kept with the release rather than at the repository root.
Clients are unaffected — they fetch `simple/`, `index.yaml`, `repodata/` or
`SHA256SUMS` — but there is no human-browsable page at the root of a bucket-hosted
repository yet.

## Status

Phase 2 is complete and Phase 3 signing is implemented. Concretely: git-backed
workspaces with `init`, `setup`, `add`, `plan` and `apply`; immutable blobs;
reviewable plans; publication ledgers; per-repository managed release switching;
`auto`, `pr` and signed-`approval` gates; encrypted local RSA4096 OpenPGP keys
with `keys new|publish|audit|rotate`; receipt-backed Debian key rotation; and
placement-level `promote` and `yank`.

Review gates read GitHub, GitLab, Forgejo and Gitea, and `snailmail ci` emits a
GitHub Actions or GitLab CI pipeline derived from the workspace.

Replacing an existing managed release needs an atomic directory-entry exchange,
so that path is implemented on Linux and macOS; creating a first release is
portable. There is no Windows build yet.

Additional key backends, more formats, `import`, and an interactive setup remain
Phase 3 work. [ARCHITECTURE.md](ARCHITECTURE.md) is the implementation contract
and [PLAN.md](PLAN.md) the broader design.

## Promotions and yanks

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

## Auditing what is published

`snailmail check` is a read-only integrity audit of every retained package
version, including yanked and pruned versions. It verifies local CAS bytes or
fetches the configured S3 authority into temporary storage, reparses native
package facts, and revalidates historical publication bindings. Upstream release
discovery remains unavailable until releases are modeled. `check --origins`
re-fetches explicitly adopted URLs and compares their pinned bytes; default
checks remain offline from external sources. Origin checks process at most four
sorted records per run; `--origin-offset` selects subsequent batches.

## Importing an existing repository

Most people arrive with a repository already published somewhere. `import` reads
its index and records every artifact it names, rather than adopting each by hand:

```sh
snailmail import --project six --public-origin --dry-run python https://pypi.org/
snailmail import --project six --public-origin python https://pypi.org/
```

Each artifact goes through the same path as `adopt`: fetched, checked against the
digest its index published, and recorded with its origin URL so it can be refetched
later. Anything the index names but does not publish a SHA-256 for is skipped and
reported — a locked artifact is pinned to a digest someone stated in advance, and
one computed from the bytes a download happened to return would prove only that the
download was self-consistent.

One artifact failing does not abandon the rest, so a repository with a broken file
imports the other 47 and names the one that failed.

PyPI today. Debian and Helm indexes are already parsed by `doctor`, so those are
reading work rather than design work.

## Adopting an artifact from a URL

`snailmail adopt --sha256 HEX --public-origin REPOSITORY URL` records one
explicitly selected artifact in an existing owned repository. The lowercase
SHA-256 pin is mandatory; `--public-origin` confirms that the complete requested
URL is non-secret and may be committed and printed. Lock schema 2 retains that
URL, plans display every visible adopted acquisition, and `--dry-run` validates
up to 128 MiB without changing CAS or lock state. Adoption currently requires
the local blob store and does not claim authorship, build provenance, source
signatures, or historical snailmail publication.

## Inspecting a workspace

`snailmail status` also reports size: each repository's lock in bytes, the count
and total size of the distinct artifacts it binds, and the workspace's lock total
with the largest repository named. The lock is parsed whole on every plan and
every apply, so its size is the number that predicts where a workspace stops
being comfortable — and which repository to split when it does.

`snailmail status` reports committed workspace evidence without contacting
hosts or providers. Human output summarizes visible and retained versions,
visible publication-binding completeness, and whether a managed deployment
receipt is recorded; `--json` emits the same deterministic schema for
automation. A receipt is evidence of a prior successful apply, not proof that a
host currently serves those bytes.

`snailmail rollout` answers when each version reached a client, derived from the
publication ledger rather than stored anywhere. The ledger already records one
append-only entry per publication, so the date is read back rather than kept a
second time. A version is listed with the date it was first published, the
number of published trees that have carried it, and whether the repository still
serves it; `--withdrawn` includes versions that were published and later yanked
or pruned, because publication is immutable even when the offer is not.

`snailmail ci github` and `snailmail ci gitlab` emit a pipeline that publishes
this workspace, to stdout rather than to a file: it carries decisions snailmail
cannot make — which registry to pull verification images through, which secret
names a project uses — and a file the tool owned would be rewritten over an
operator's edits. What it does derive is what the workspace already says: which
signing keys need materialising, whether a foreign architecture needs emulation,
and which repositories publish into a directory something else must serve. Both
providers derive the same facts; only the rendering differs, and it differs more
than wording. A GitLab runner has no Docker daemon, so client verification needs
one as a service; its jobs share no filesystem, so what apply builds is declared
as an artifact; and Pages there serves a job artifact rather than a moved ref, so
there is no orphan commit.

## Two runners at once

The workspace lock is a file inside the checkout, so it serialises operations on
one machine and not two. What protects a repository when two CI runners publish
at the same time is the conditional commit: each states the revision it observed,
and the second to arrive is refused because that is no longer what is live.

So the failure mode is **one run fails, not one run waits**. It fails as a stale
plan, which is a retry signal — replanning against what is actually live and
applying again succeeds. A pipeline that publishes from more than one place at once
wants a concurrency group so this is rare rather than routine; the generated
workflows set one.

Two things worth knowing. Staging is *not* exclusive, deliberately: two runners can
both stage, because a stage writes only under its own identifier and touches nothing
a client reads. And a local host cannot be shared at all — its output path is
relative to its workspace — so this only arises for object storage and Pages, where
two runners can name the same bucket and prefix or the same repository and branch.

## How large a workspace can get

A repository lock is parsed whole on every plan, apply, status and check, so its
size is what decides how long those take and how much memory they need. Measured
at roughly 385 bytes per package-version, with parsing costing about one and a half
times the file in heap:

| package-versions | lock file | parse | heap |
|---|---|---|---|
| 2,000 | 0.8 MB | 5 ms | 1 MB |
| 20,000 | 7.7 MB | 44 ms | 12 MB |
| 100,000 | 38.5 MB | 226 ms | 59 MB |

snailmail refuses a lock over **128 MiB** — about 330,000 package-versions — and
says so, naming the repository, the size and what to do:

```
repository "repos/apt.lock.toml" has a 200 MiB lock, over the 128 MiB limit, and
parsing it needs roughly 300 MiB of memory on every plan and apply: prune retained
versions, split the repository, or set SNAILMAIL_MAX_LOCK_BYTES to proceed anyway
```

That is the honest state of things: one lock per repository is the current design,
and a workspace past this size wants the lock sharded per package rather than a
larger limit. The limit exists so that a workspace which has outgrown the design
finds out in a sentence instead of getting slower until something is killed.
`snailmail status` reports every lock's size, so the number can be watched before
it becomes a refusal.

Artifacts themselves are not held in memory — they stream from content-addressed
storage — so the ceiling is index and lock size, not repository size. Generated
indexes are held whole, which for Debian and yum is the binding constraint at
around a million package-versions.

## Collecting superseded releases

An object store keeps every revision it has ever published: a publication writes a
whole tree under `.snailmail/releases/<tree>/`, and nothing removes the previous
one. A project publishing daily accumulates a copy a day.

```sh
snailmail collect                 # report what would be removed
snailmail collect --keep 3 --yes  # remove it, retaining three recent revisions
```

Reporting is the default; `--yes` deletes. Three things always survive whatever
`--keep` says: the live revision, whatever its rollback depends on, and any
revision the ledger records within `--keep`. The first two are established by
reading the host rather than the workspace, so a checkout whose ledger is behind
cannot delete what is being served.

Note that with only two publications nothing is collectable — both are protected,
the live one and the one it rolls back to. Local directories and GitHub Pages have
nothing to collect and say so: the first leaves nothing behind, and the second
leaves unreachable objects to git.

Collection is the one operation that needs `s3:ListBucket`, so it may run under a
different credential from publishing.

## Inspecting someone else's repository

`snailmail doctor URL` needs no workspace and inspects a public HTTPS PyPI,
Debian, or Helm repository. It parses bounded native indexes, follows at most the
configured artifact limit, and checks referenced availability, size, SHA-256,
archive validity, and package identity. Use `--project` for PyPI artifacts and
`--suite` for a Debian base URL. Debian Release signatures and Helm provenance
are explicitly reported as unverified in this initial slice. Runs inspect at
most four artifacts, cap each expanded archive at 64 MiB, and stop after two
minutes.

## Raw repositories

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

## Signing keys

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

Every format the knowledge bundle records as signable is signed, each in the
form its own clients read: Debian publishes `InRelease` and `Release.gpg`, yum an
armored key beside a detached `repomd.xml.asc`, Alpine one signature per
architecture index under the key filename its index names, and Helm a `.prov`
per chart beside the archive it covers. The published key differs with the
client — apt installs a binary keyring, dnf imports an armored export, apk holds
a bare RSA key by filename — so `keys attach` refuses a key whose algorithm the
format's clients cannot check. Every signature is verified before it is
published, because a repository carrying one that does not check out is worse
than an unsigned one: a client reports it as tampering.

## Rotating a signing key

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

## What plan requires

`plan` requires the manifest, configured locks, publication ledgers, and
deployment receipts to be committed in a complete, non-shallow Git repository. `apply`
executes the reviewed plan without replanning, verifies staged repository
bytes, commits its exact publication ledger records with a compare-and-swap,
and publishes through the selected host's conditional release switch. After
canonical verification succeeds, apply commits a deployment receipt separately
from the pre-effect publication ledger. S3 keeps
the verified tree under an immutable digest prefix and conditionally updates a
small root index that points clients at that tree.

## Publishing to object storage

Object storage serves PyPI, Helm and unsigned yum repositories. Setup uses the
standard AWS credential chain; no
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

### What the credential has to be allowed to do

Publishing needs, scoped to the configured prefix:

- `s3:GetObject` — reading back what it wrote, to verify it
- `s3:PutObject` — writing artifacts, indexes and the root object
- `s3:DeleteObject` — removing an abandoned stage, and removing the root object
  when a restore has to leave a repository with none

It does **not** need `s3:ListBucket`. Every operation on the publishing path
addresses an object by a key snailmail already knows, which is what lets a
publication be verified without trusting a listing.

`s3:ListBucket` is needed only to discover state a publication has superseded —
collecting old releases. That is a separate operation and may run under a separate
credential, so a publishing role stays as narrow as the list above.

The bucket or gateway must serve the configured prefix, including
`.snailmail/stages/` during pre-publication verification. Use `--endpoint` and
`--use-path-style` for compatible object stores. All non-loopback S3 API and
package client endpoints must use HTTPS. Configure a
bucket lifecycle rule to expire abandoned `.snailmail/stages/` objects after a
grace period; immutable `.snailmail/releases/`, `.snailmail/manifests/`, and
`.snailmail/restores/` objects must not use that short-lived rule.

A private object-storage repository uses a Basic-auth gateway and a short-lived
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

## Publishing to GitHub Pages

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

## Review and approval gates

For a PR gate, initialize the workspace with its reviewed state repository and
configure `--gate pr`. Apply verifies that the exact Git revision was merged by
a PR and remains reachable from that repository's default branch.

```sh
go run ./cmd/snailmail init --name example --forge-repo example/state

# On a forge other than GitHub, name it. The reference shape alone cannot say
# which service to ask whether a revision was reviewed, and omitting this means
# github.com.
go run ./cmd/snailmail init --name example \
  --forge gitlab --forge-repo acme/platform/state
go run ./cmd/snailmail init --name example \
  --forge gitea --forge-repo acme/state --forge-host git.acme.example
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

## Status pages

Render the read-only public matrix and machine-readable status from committed
locks, ledgers, deployment receipts, and an optional current plan:

```sh
go run ./cmd/snailmail dashboard --output site
```

## Build layout and binary size

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

## Container image and CI examples

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
  targets, public or private object storage, or public GitHub Pages with a
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
