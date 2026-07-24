# snailmail

> relaxed package delivery

One tool to **create, host, sign and operate package repositories** of any
format — apt, dnf, apk, PyPI, npm, Helm, OCI, Cargo, Go, Maven, Nix, or plain
artifacts — on hosting you choose, and to **publish into repositories you
don't own** — AUR, Homebrew, nixpkgs, npmjs, PyPI, ghcr.

**Status: Phase 1 local reconciliation.** The current implementation builds,
structurally verifies, serves, and client-tests deterministic static PyPI,
Debian, and Helm repositories. Git-backed workspaces also support local
`init`, `setup`, `add`, `plan`, and `apply` workflows with immutable blobs,
reviewable plans, publication ledgers, and per-repository managed release
switching. Replacement of an existing managed release is currently implemented
only on Linux. Signing, remote hosts, and PR or approval gates remain future work. See
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
and publishes those same bytes through a managed release switch.

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
- **Local first.** `snailmail setup` currently records deterministic local
  repository configuration; hosting and key provisioning remain future work.

```
              apt      dnf      apk      aur      aur-bin  brew     nixpkgs
  ttysvg      0.1.2    0.1.2 ✗  0.1.2    0.1.2    0.1.2    0.1.2    0.0.7 ⚠
  exex        0.3.2    0.3.2 ✗  0.3.2    0.3.2    0.3.2    0.3.2    —
  cnvrt       0.0.3    0.0.3 ✗  0.0.3    0.0.3    0.0.3    0.0.3    —
  snailrace   0.0.5    0.0.5 ✗  0.0.5    0.0.5    PR #12   0.0.5    —

  ✗ verify failing   ⚠ lagging   PR # gate pending
```
