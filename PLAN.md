# snailmail — relaxed package delivery

A single tool to **create, host, sign and operate package repositories** of any
format — apt, dnf, apk, PyPI, npm, Helm, OCI, Cargo, Go, Maven, Nix, or plain
artifacts — on hosting you choose, plus **publish into repositories you don't
own** — AUR, Homebrew, nixpkgs, npmjs, PyPI, ghcr.

Status: **active roadmap**. Phases 0 through 2 are implemented; Phase 3 signing
and repository operations are in progress. `README.md` records the exact current
implementation surface.

---

## 1. Why

Every ecosystem has its own publishing tool, and each one knows about exactly
one format, one hosting model, and one signing scheme. Running more than one is
a pile of bespoke scripts with no shared vocabulary, no shared state, and no
single answer to "what is published where, at which version?"

The three problems that motivate this, in priority order:

1. **No answer to "where is `ttysvg 0.1.2` actually live?"** It takes several
   repos and several CI tabs. Drift is invisible until a user reports it —
   a flake pinned at `0.0.7` while releases reached `0.1.2`, unnoticed for
   months.
2. **Publishing policy is workflow topology.** "AUR needs a PR, apt does not"
   is encoded in the *shape* of separate YAML files. Changing policy means
   restructuring workflows; adding a target means writing a new one.
3. **Nothing verifies the result.** Almost no pipeline installs from what it
   just published. An Ed25519 repo signing key that RPM's parser cannot read is
   a config that "succeeds" every time and works for nobody.

And one that shows up the moment you want your own repository at all:

4. **Standing up a repo is a research project.** Getting a correct, signed apt
   or dnf repository onto static hosting means learning `InRelease`, `repomd`,
   keyring formats, and which algorithm each client can parse — days of work,
   repeated per format, mostly rediscovering the same traps.

snailmail exists to fix those four. It is explicitly **not** an attempt to
rewrite `nfpm`, `goreleaser`, `reprepro`, or `createrepo_c`.

## 2. Principles

**The format layer is a pure function.** `Build(placements, key) → fs.FS`. No
network, no clock, no daemon; same inputs, byte-identical tree. Everything else
in this design is downstream of that one decision.

**Static-first, server-optional, never server-required.** Most ecosystems have
a static read protocol (§5). A static apt repo is a real apt repo, not a
degraded one. The server (§11) exists only for *write* protocols and auth.

**Git is the state.** A repository's contents are a committed lockfile; the
served index is a build artifact regenerated from it. Rollback is `git revert`.

**Observed state is derived, never stored** — for anything you don't own. No
local database of what's live on someone else's server.

**A plan is a reviewable artifact.** `plan` writes a file; `apply` consumes
*that file*, not a freshly computed one. Otherwise you approve one thing and
ship another.

**A target that cannot prove an end user can install from it is not
implemented.** `Verify` is on the interface, not in the backlog.

---

## 3. The domain model

This is the heart of the design. The word "package" is used for at least four
distinct things in this space, and every tool that conflates them ends up with
special cases it cannot explain.

```
   Source ──watch──▶ Release ────────┐          Remote (unmanaged repo)
     │              upstream 0.1.2   │          roles: observe|source|target
     │ fetch                         │                      ▲
     │                          Mapping                     │
     │                     name + version + deps            │
     │                        per Format/Distro             │
     ▼                              ▼                       │ Recipe / Upload
   Blob ◀───────────────── PackageVersion ──────────────────┘
  sha256:…    constitutes  deb:ttysvg@1:0.1.2-1~bookworm1
   + facts                         │
   (arch, deps)                    │ Placement (repo, track, distro)
                                   ▼
                              Repository ──Index──▶ Host
                              Format + Key
```

### 3.1 The nouns

| | Concept | One line |
|---|---|---|
| 1 | **Product** | the upstream thing in the world |
| 2 | **Release** | an upstream version of it |
| 3 | **Source** | where releases are watched and bytes fetched |
| 4 | **Blob** | content-addressed bytes + parsed facts |
| 5 | **Format** | a packaging ecosystem's rules, as code |
| 6 | **Package** | a format-scoped named identity |
| 7 | **Mapping** | Product → Package: name, version, deps, per destination |
| 8 | **PackageVersion** | a version of a Package, in repository terms |
| 9 | **Distro** | a distribution release the repo serves |
| 10 | **Track** | the promotion axis |
| 11 | **Placement** | a PackageVersion is visible *here* |
| 12 | **Repository** | a format-typed collection you own |
| 13 | **Remote** | a repository you don't own, with roles |
| 14 | **Rendering** | Index, or Recipe/Upload |
| 15 | **Requirement** | an abstract dependency |
| 16 | **Key** | a signing identity |
| 17 | **Host** | where a built tree lands |
| 18 | **Rollout** | one Release fanned across destinations |
| 19 | **Plan / Change** | a reviewable, executable diff |
| 20 | **Attestation** | signatures, SBOM, provenance |

**Product** — the upstream thing that exists in the world: `ttysvg`. Homepage,
license, source repo, maintainer. Format-agnostic, repository-agnostic.
**Optional**: a repository can hold packages with no Product behind them
(someone else's `.deb`, a vendored wheel). Nothing in the model may require one.

**Release** — an *upstream* version of a Product: `ttysvg 0.1.2`. What upstream
declared, with its own version string, date, notes, and source assets. This is
what "is there a new version?" asks about. Independent of any repository.

**Source** — where Releases are discovered and bytes are fetched. GitHub
Releases, a git tag pattern, a build step, a URL template, a local directory,
an upstream distro repo. Two capabilities, separable: *watch* (enumerate
releases) and *fetch* (retrieve assets).

**Blob** — bytes, content-addressed by `sha256:…`. Immutable by construction.
Carries derived **facts** parsed out of the artifact itself: format, package
name, native version, architecture, platform tags, declared dependencies. A
`.deb` knows its own arch; a wheel knows its platform tag. Never ask the user
for what the bytes already say.

**Format** — a packaging ecosystem's rules, as code: deb, rpm, apk, pypi, npm,
helm, oci, cargo, go, maven, nuget, nix, raw. Not a string on a repository — a
first-class object owning version mapping and comparison, name normalization,
dependency translation, index generation, signing requirements, and the install
snippet (§5). Formats are the unit of extension: adding one adds a whole
ecosystem without touching the model.

**Many repositories share a Format.** `apt-stable` and `apt-internal`, a public
PyPI and a private one, per-customer or per-team repos, a staging mirror. The
Format is the code; the Repository is the deployment. Nothing about the design
assumes one repository per format, and the wizard is happy to be run twice.

**Package** — a *format-scoped named identity*: "the deb named `ttysvg`", "the
PyPI project `ttysvg`", "the Helm chart `ttysvg`". Identity is
`(namespace, format, name)`. One Product maps to **many** Packages —
`ttysvg` and `ttysvg-bin` on AUR, `ttysvg` and `ttysvg-doc` on deb — and that
1:N edge is data, not convention (§3.5).

The **namespace** exists so the deb named `ttysvg` you build and the deb named
`ttysvg` you vendored from a third party are not accidentally the same object.
Default: one namespace per workspace, invisible until you mirror something.
Repositories declare which namespaces they draw from, which is how two
repositories of the same format can serve genuinely different packages under
identical names.

**Mapping** — the Product → Package edge, carried as data because none of it is
derivable: the **name** it takes in that destination, its **role** (`main`,
`bin`, `dev`, `doc`, `debug`, `source`), the **version transform**, and the
**dependency translation**. See §3.5, §3.4, §3.7 respectively. Mappings are also
what make *observation* possible — to ask "is my thing in nixpkgs?" you must
first know what it is called there.

**PackageVersion** — a version of a Package as it exists *in repository terms*:
`1:0.1.2-1~bookworm1`. Distinct from the Release it came from, because every
format mangles versions differently, adds its own revision/epoch space, and
sometimes needs a distinct build per distribution (§3.4, §3.6).

> A PackageVersion is a **set** of Blobs, not one Blob. One `.deb` per arch;
> an sdist plus N wheels; a chart plus its provenance file. Modelling it as a
> single artifact breaks on the second format you add.

**Distro** — a distribution release a repository serves: `(family, release)` —
`debian/bookworm`, `ubuntu/24.04`, `el/9`, `fedora/40`, `alpine/3.20`. Maps to
the deb *suite*, the rpm `$releasever`, the apk *branch*. Formats without the
notion (pypi, npm, helm, cargo) have exactly one, and it disappears.

**Track** — the promotion axis: `stable`, `testing`, `nightly`. Maps to deb
suites, npm dist-tags, OCI tag conventions, Helm's nothing-at-all.

> **Track and Distro are different axes** even though Debian mushes both into
> one path segment — `bookworm` is a Distro and `stable` is a Track, and Debian
> uses one directory name for whichever you asked for. Conflating them is why
> "promote to stable" and "also build for trixie" feel like the same operation
> in existing tools and then don't behave like it. Keep them separate; render
> them into whatever layout the format demands.

**Placement** — the fact that a PackageVersion is present in a Repository, on a
Track, for a Distro. `(repository, track, distro, component?, packageVersion)`.

> Placement is the concept that makes the whole thing work. A PackageVersion
> exists once; Placements say where it is visible. **Promotion** is adding a
> Placement. **Retention** prunes Placements. **Yanking** removes Placements
> while keeping the version recorded. Blobs are garbage-collected when no
> Placement reaches them. Without it, promoting `testing → stable` means
> rebuilding or copying, and every one of those operations needs its own code.

**Architecture is not a coordinate.** It is a Blob fact — a `.deb` states its
own arch, a wheel its platform tag — and the index generator files it. Asking
the user for what the bytes already say is how arch metadata goes wrong.
Distro *is* a coordinate, because the same bytes may serve bookworm and trixie,
or may not, and nothing in the file can tell you which (§3.6).

**Repository** — a named, format-typed collection of Placements that you
publish and own. Format, Host, Key, tracks, retention policy, gate, visibility.

**Remote** — a repository you do **not** own, with one or more **roles**:

| Role | Meaning | Examples | Needs credentials |
|---|---|---|---|
| `observe` | read-only "is my thing there, at what version?" | nixpkgs, crates.io, homebrew-core | no |
| `source` | pull artifacts from it | Debian, PyPI, an internal repo | rarely |
| `target` | push recipes or uploads into it | AUR, your Homebrew tap, npmjs, ghcr | yes |

One Remote can hold several roles — a Homebrew tap is `target` *and* `observe`.
Splitting roles from repositories is what lets the matrix show nixpkgs (pure
observation, nothing to publish) beside AUR (a real publishing target) without
either being a special case.

**Rendering** — what a PackageVersion turns into for a destination. Two shapes,
one idea:

| Destination | Rendering | Delivery |
|---|---|---|
| Repository you own | **Index** + pool of blobs | `Host.Sync(tree)` |
| Remote, role `target` | **Recipe** (`PKGBUILD`, formula, `flake.nix`) or **Upload** | git push / native API |

**Requirement** — an abstract dependency of a PackageVersion:
`(name-or-capability, constraint, kind)` where kind is `build`, `runtime`,
`optional`, or `conflict`. Written once, translated per Format and Distro
(§3.7). Also *read* from Blob facts, since a built `.deb` already declares its
`Depends`.

**Key** — a signing identity: algorithm, usage, expiry, a `KeyRef` to private
material in some backend, and the set of public forms each format demands.

**Host** — where a built tree lands. GitHub Pages, S3/R2/GCS, `ssh+rsync`, a
git branch, GitHub Releases, an OCI registry, a local directory.

**Rollout** — one Release fanned out across many destinations, each with its
own gate and status. This is the object the status matrix visualizes and the
thing you mean by "ship 0.1.2": *6 of 8 done, dnf pending approval, AUR PR
open*. Without it, a release is only ever inferred from N independent states.

**Plan / Change** — a computed, reviewable set of Changes; the unit `apply`
consumes. Changes are marked **reversible** or not (§9).

**Attestation** — signatures, SBOMs, build provenance attached to a
PackageVersion. Needs a slot in the model from day one; needs no implementation
until Phase 5. Retrofitting provenance into a model that has no place for it is
how you end up with a second, parallel metadata system.

### 3.2 What deliberately does *not* exist

- **No "channel".** PLAN's original `channel` was doing three jobs: owned
  repository, foreign publishing target, and review policy. It is now
  Repository, Remote(`target`), and Gate.
- **No arch coordinate.** A Blob fact, not user-supplied structure.
- **No state database.** Lock for owned, live query for foreign.
- **No "artifact type" enum.** Format is a Blob fact, and `raw` is a real
  format, not an absence of one.
- **No assumption of one repository per format.** The Format is code; the
  Repository is a deployment; the relationship is 1:N.
- **No universal package name.** A Product has no canonical name across
  ecosystems — only a Mapping per destination (§3.5).

### 3.3 Identity and references

A canonical ref syntax, because it shows up in every command and every diff:

```
  ttysvg                             Product
  ttysvg@0.1.2                       Release (upstream)
  deb:ttysvg                         Package
  deb:ttysvg@1:0.1.2-1~bookworm1     PackageVersion
  apt/stable/bookworm                Track × Distro in a Repository
  apt/stable/bookworm:deb:ttysvg@…   Placement
  sha256:9f2c…                       Blob
```

### 3.4 Versions are per-format, twice over

Two operations that look generic and are not:

**Mapping.** `Format.MapVersion(upstream) → native`. The same upstream
`0.1.2-rc1` is `0.1.2~rc1-1` in deb and rpm, `0.1.2rc1` in PyPI, `0.1.2-rc1` in
npm. Get this wrong and prereleases sort *above* finals, which is silently
catastrophic.

**Comparison.** `Format.CompareVersions(a, b) → int`. `dpkg --compare-versions`,
`rpmvercmp`, PEP 440, semver and Nix all disagree. Retention ("keep the newest
five"), lag detection, and "is this a downgrade?" all depend on it. **There is
no generic version comparator and the tool must never pretend otherwise.**

### 3.5 Names are per-destination too

A Product has **no canonical name**. The same thing is:

| Destination | Name | Why |
|---|---|---|
| deb | `ttysvg`, `ttysvg-doc`, `libttysvg-dev` | split by role, `lib*`/`*-dev` conventions |
| rpm | `ttysvg`, `ttysvg-devel` | `-devel`, not `-dev` |
| AUR | `ttysvg`, `ttysvg-bin`, `ttysvg-git` | source/binary/VCS variants are separate packages |
| PyPI | `tty-svg` → normalized `tty_svg` | PEP 503 lowercases and folds `-_.` |
| npm | `@shellcell/ttysvg` | scoped |
| OCI | `ghcr.io/shellcell/ttysvg` | registry path, not a name |
| Homebrew | `shellcell/tap/ttysvg` | tap-qualified |
| Python lib on deb/rpm | `python3-ttysvg` | ecosystem prefix conventions |

Three mechanisms, in order of precedence:

1. **`Format.NormalizeName(n)`** — mandatory canonicalization the ecosystem
   itself imposes. PEP 503 folding, npm's lowercase-only rule, Debian's charset.
   Not a choice; getting it wrong produces a repository clients cannot resolve.
2. **Convention templates** per (format, role) — `{name}-dev` for deb,
   `{name}-devel` for rpm, `{name}-bin` for AUR, `python3-{name}` for a Python
   library. Right by default, so the common case needs no configuration.
3. **Explicit override** in the Mapping, which always wins.

Because names differ, `observe` on a Remote needs the mapping too. "Is ttysvg
in nixpkgs?" is unanswerable without knowing it is `ttysvg` there and
`ttysvg-bin` on AUR — which is precisely why the status matrix in every
homegrown script quietly reports "missing" for things that are present.

### 3.6 Architectures and distribution releases

Two axes that look alike and behave completely differently.

**Architecture is derived.** `amd64`, `arm64`, `armv7`, `riscv64`, plus
platform tags for wheels and `os/arch/variant` for OCI. The Blob states it. The
index generator files it. It never appears in a Placement.

**Distribution release is declared.** A repository serves a *matrix*:

```
  apt      debian/{bookworm,trixie}, ubuntu/{22.04,24.04}  × {amd64, arm64}
  dnf      el/{8,9}, fedora/{40,41}                        × {x86_64, aarch64}
  apk      alpine/{3.19,3.20,edge}                         × {x86_64, aarch64}
  pypi     —                                               (wheel tags carry it)
```

The interaction that matters: **the same upstream Release often needs a
different build per distro** — different glibc, different soname, different
dependency names. When it does, those are *different PackageVersions*
(`0.1.2-1~bookworm1` vs `0.1.2-1~trixie1`), each with its own Placement. When
one build serves several, it is *one PackageVersion with several Placements*.

Both cases must be cheap, because which one applies is a property of the
software, not of the tool. A model that assumes "one build per release" breaks
on the first C dependency; one that assumes "one build per distro" multiplies
storage and CI time for pure-Go binaries that never needed it.

`Format.MapVersion` therefore takes the Distro as an argument, since the
`~bookworm1` suffix *is* the distro encoded into the version string — the
convention exists precisely because deb has no other way to express it.

### 3.7 Dependencies

The hardest part, and the one where scope discipline matters most. The same
requirement is `libssl-dev` on deb, `openssl-devel` on rpm, `openssl-dev` on
apk, and `openssl` on Homebrew and Arch — and the constraint syntax differs
too: deb `(>= 1.2)`, rpm `>= 1.2`, apk `>1.2`, PEP 508 `>=1.2,<2`, npm `^1.2`.

Four layers:

1. **Constraint AST.** One internal representation, rendered per format.
   Mechanical, worth doing properly, and where the subtle bugs live —
   `^1.2` and `>=1.2` are not the same statement, and neither survives a naive
   string copy into a `Depends:` field.
2. **Capability names.** Write `openssl:dev`; a curated table resolves it per
   (format, distro). Ship the common few hundred, allow overrides, allow raw
   per-format passthrough for the long tail. **Do not attempt completeness** —
   cross-distro dependency naming is an open problem with a whole project
   (repology) devoted to observing it, and a tool that pretends to have solved
   it is worse than one that admits the table has edges.
3. **Intra-workspace deps are automatic.** `ttysvg-doc` depends on `ttysvg` at
   the same version; snailmail knows both Mappings and renders the right name
   and version in each format without being told.
4. **`verify` is the backstop.** A container that installs the package resolves
   its dependencies for real. This is why the table doesn't need to be perfect:
   an unresolvable dependency fails a smoke test before deploy rather than
   becoming a user's bug report. **Dependency correctness is enforced by
   installation, not by the table.**

Dependencies are also read *back* from Blob facts, which gives two useful
checks for free: a package whose declared Requirements disagree with what the
built artifact records, and a Placement whose dependencies are not satisfiable
by anything else placed in the same track and distro.

### 3.8 Acquisition: adopt, repack, build, or proxy

Upstream frequently already ships the artifact you want — a `.deb` attached to
their GitHub release, a wheel on PyPI, a chart in their repo. Sometimes you take
it; sometimes you must build it yourself. This is a property of the
PackageVersion, and it is **four cases, not two**:

| Mode | Bytes authored by | You store them | Use when |
|---|---|---|---|
| `adopt` | selected third party | ✅ | you explicitly trust pinned external package bytes |
| `repack` | you, payload theirs | ✅ | upstream ships a tarball/binary, not a package |
| `build` | you, from source | ✅ | you need your own deps, arches, or patches |
| `proxy` | upstream | ❌ — index links to theirs | you want the index, not the bandwidth |

**`adopt` is the common case and the one people hand-roll badly.** You fetch a
selected third party's `.deb`, verify its operator-supplied pin, and place it in
*your* repository. Your index, their bytes. Cheap and correct — until it isn't, and the failure modes are worth
encoding as preflight checks rather than discovering later:

- upstream's version string may violate your repository's conventions (no epoch
  discipline, a `v` prefix, a date-based scheme that sorts wrong next to yours);
- their dependencies target *their* distro matrix, not yours — an artifact built
  for `ubuntu/24.04` may simply not resolve on `debian/bookworm`;
- they may not sign, or sign with a key your clients don't trust — note that
  adopting means **your** repository signature vouches for bytes you did not
  build;
- they can delete or retag a release out from under you.

`snailmail add --from <url>` therefore always pins `sha256:` in the lock, and
`check` re-fetches and compares. **Upstream silently changing the bytes behind a
tag is a supply-chain signal**, and pinning is what turns it from invisible into
a failing check.

**`proxy` only works for some formats**, and the reason is mechanical: can the
index name an absolute URL somewhere else?

| Proxyable | Not proxyable |
|---|---|
| pypi (`href`), npm (`dist.tarball`), helm (`urls:`), cargo (`dl`), raw, go (302) | deb (`Filename:` is repo-relative), rpm (`location href`), apk, maven, oci |

Proxying costs no storage and no bandwidth, and buys a dependency on someone
else's uptime, retention policy, and TLS. It is right for an internal index that
curates public packages; it is wrong for anything that must keep working when
upstream has a bad day. Default to `adopt`.

**`repack` is where `nfpm` earns its place** — upstream ships a static binary in
a tarball, you produce the `.deb`, `.rpm` and `.apk` from one declaration, with
*your* dependency names (§3.7) and *your* distro matrix (§3.6). For statically
linked CLIs this is the mode that matters most, and it makes one upstream
Release fan out into a dozen PackageVersions from a single source asset.

The mode is per (Product, destination), not per Product: adopt upstream's wheel
for PyPI, repack their tarball for deb and rpm, proxy their chart. That
combination is normal, and it is exactly what a Mapping (§3.1) is for.

### 3.9 Immutability rules

| Concept | Mutable? |
|---|---|
| Blob | never — content-addressed |
| PackageVersion | frozen once published anywhere; to change it, bump the revision |
| Placement | freely — this is promotion, retention, yanking |
| Repository config | freely |
| Release | upstream's business |

PackageVersion state is `draft → published → yanked`. Republishing different
bytes under a version that was ever public is forbidden, because npm, PyPI and
crates.io forbid it forever and the failure mode elsewhere is a poisoned cache
that nobody can debug.

---

## 4. Three layers, one pure function

```
  Blobs ──▶ [ Format ] ──▶ file tree ──▶ [ Host ] ──▶ live repository
             pure fn         bytes         sync
                 ▲
                 │
                Key
```

Because the format layer is pure and returns a *static file tree*:

- GitHub Pages hosting is free — dump the tree.
- So is S3, R2, Netlify, `rsync`, a USB stick.
- Local preview is `http.FileServer` over the result.
- Verification is real: serve the **staged** tree to a container and install
  from it, before anything is deployed.
- `plan` can diff trees byte-wise.
- The server never becomes load-bearing.

## 5. Formats

The bet in §4 only pays if ecosystems have static read protocols. Most do.
This table is the tool's core competence and belongs in code, not documentation.

| Format | Static read | Index shape | Signing | Tier |
|---|---|---|---|---|
| **pypi** | ✅ | PEP 503 HTML / PEP 691 JSON | none — PyPI dropped GPG in 2023 | 1 |
| **deb** | ✅ | `dists/*/Packages`, `pool/` | `InRelease` + `Release.gpg`, binary keyring | 1 |
| **helm** | ✅ | `index.yaml` + `.tgz` | `.prov` (GPG) | 1 |
| **raw** | ✅ | generated listing + `SHA256SUMS` | none — not an ecosystem, no client checks a signature | 1 |
| **rpm** | ✅ | `repodata/repomd.xml` | `repomd.xml.asc` implemented; per-RPM `--addsign` belongs to the package builder | 1 |
| **apk** | ✅ | `<arch>/APKINDEX.tar.gz` | RSA only, filename is load-bearing — not implemented | 1 |
| **cargo** | ✅ | sparse index | none | 2 |
| **go** | ✅ | GOPROXY `@v/` layout | checksum db | 2 |
| **maven** | ✅ | `maven-metadata.xml` | `.asc` per artifact | 2 |
| **nuget** | ✅ | v3 flat container | none | 2 |
| **nix** | ✅ | binary cache: `.narinfo` + `nar/` | ed25519 `Sig:` — required | 2 |
| **npm** | ⚠️ | packument JSON + tarballs | none | 2 |
| **oci** | ❌ | Distribution v2 API | cosign | registry-only |

Two honest asterisks:

**npm** reads fine statically, but scoped names (`@scope/pkg`) are URL-encoded
as `%2f`, and many static hosts normalize that into a path separator. Emit both
layouts; let `verify` catch which one the chosen host actually serves.

**OCI cannot be static.** Manifests require an exact `Content-Type` and static
hosts serve by file extension. Don't fight it: for containers and OCI-Helm the
Host *is* a registry (ghcr.io, ECR, Zot, Harbor) and `Sync` is implemented as
push. Same interface, different delivery.

**Tier is a promise, not a vibe.** Tier 1 means CI runs a container that
installs from a freshly generated repository using the exact instructions the
tool prints. Tier 2 means it generates and is spot-checked. Tier 3 is an
out-of-tree plugin. No format claims Tier 1 without the test.

The Format boundary is code: the interface and its registry live in `formats/`,
with a conformance suite every registered format inherits. `ARCHITECTURE.md` §6
is the normative shape — in particular, a single `BuildIndex(placements, key)`
call was rejected there because formats like RPM sign in several rounds, and
`Verify` lives outside the format because formats own no containers. Name
mapping, version transforms, and dependency rendering join the interface when
the Product/Mapping model exists (§3.5, §3.7), not before.

## 6. Git is the state

> **A repository's contents are a committed lockfile. The served index is a
> build artifact regenerated from it.**

```toml
# repos/apt.lock.toml
[[placement]]
track = "stable"
package = "deb:ttysvg"
version = "1:0.1.2-3"
blobs = ["sha256:9f2c…", "sha256:41ab…"]     # amd64, arm64
release = "ttysvg@0.1.2"                      # provenance, optional
```

`snailmail add apt ./ttysvg_0.1.2_amd64.deb` does not mutate a live index. It
stores the blob, appends a stanza, and commits. CI rebuilds and syncs.

What that buys, all at once:

- **Rollback is `git revert`** — for a package repository this is close to
  magic, and nothing else in the space offers it.
- **Review is a PR diff** on a file a human can read, so the `pr` gate works
  for repositories you own, not only for recipes.
- **Reproducible**: the index is a deterministic function of the lock.
- **Retention and promotion are lock edits** — a diff, not a destructive act.
- **Audit is `git log`**: who published what, when, approved by whom.

**Blobs do not go in git.** The lock holds `sha256:…`; bytes live in a
content-addressed store. Default: **ghcr.io via ORAS** — free for public repos,
natively content-addressed, writable from Actions with the stock
`GITHUB_TOKEN`, no bucket to provision. Alternatives: GitHub Releases on a
pinned tag, S3/R2, or local for air-gapped use. `apply` materializes blobs into
`pool/` at sync time.

**Two state models, divided strictly by ownership.** The lock is desired state
for repositories you own; the live index is observed. For Remotes there is no
lock at all — query every run. The first person to blur these will introduce a
state file. Don't.

**Concurrency.** Two CI runs adding packages will conflict on the lock. Keep
stanzas sorted, one placement each, so git usually merges them; add
retry-with-rebase and a documented Actions `concurrency:` group per repository.

## 7. `snailmail setup <format>`

The wizard is the adoption surface, so it produces five things, not one:

1. **Repository definition** in `snailmail.toml`.
2. **A signing key**, with a format-appropriate algorithm (§8), or a reference.
3. **Provisioned hosting** — creates the `gh-pages` branch, the bucket, the
   Pages config; prints the DNS records it cannot create.
4. **CI wiring** — a generated workflow that runs `plan`/`apply` on merge.
5. **Consumer install instructions**, generated — the deb822 `.sources` stanza,
   the `pip.conf` block, the `helm repo add`. Hand-written install docs go stale
   and advertise packages the repo doesn't serve; these come from what was
   actually built, and are *the same string the verify container executes*. They
   cannot drift.

```
$ snailmail setup deb

  name              apt
  where             ▸ GitHub Pages          free, ~1 GB soft limit
                      Cloudflare R2         no egress fees
                      S3 / MinIO
                      ssh + rsync
                      GitHub Releases       stable per-tag URLs
                      local directory
  tracks            stable, testing
  signing key       ▸ generate new (rsa4096 — ed25519 is unreadable by EL9 rpm)
  gate              auto
  retention         keep 5 versions per track

  writes  snailmail.toml, repos/apt.lock.toml,
          .github/workflows/snailmail-apt.yml
  ✓ created branch gh-pages, enabled Pages
  ✓ install instructions → docs/install-apt.md
```

**Hard rule: every prompt is also a flag.** The TUI is a flag-filler over a
non-interactive command, never a second code path.

```
snailmail setup deb --host github-pages --repo shellcell/packages \
  --tracks stable,testing --key new:rsa4096 --gate auto -y
```

Without this the wizard is untestable, unusable in CI, and will eventually grow
a parallel, subtly different config writer.

## 8. Keys: the compatibility table is the product

Algorithm choice is not a preference. It is a per-format correctness
constraint, and the constraints **contradict each other**:

| Format | ed25519 | rsa4096 | Note |
|---|---|---|---|
| deb | ✅ | ✅ | apt/gpgv accepts both |
| rpm | ❌ | ✅ | EL9's rpm cannot parse ed25519 OpenPGP |
| apk | ❌ | ✅ | RSA only; the public key **filename** is significant |
| nix | ✅ required | ❌ | narinfo `Sig:` is ed25519 by definition |
| maven, helm | ✅ | ✅ | |
| pypi, npm, cargo, go | — | — | no repository signing at all |

A single "repo signing key" is therefore **impossible** if you serve both rpm
and nix. Keys are per-repository, and `keys audit` turns *"your dnf repo is
signed with a key EL9 clients cannot read"* from a user's bug report months
later into a finding on day one. That check is the highest-value thing in the
tool and it is about forty lines of table.

```
snailmail keys new apt-signing --algo rsa4096 --usage sign
snailmail keys publish    # every public form: binary .gpg (apt), armored .asc
                          # (dnf), <name>.rsa.pub at the exact filename apk needs
snailmail keys audit      # expiry, usage, per-format compatibility
snailmail keys rotate debian --successor apt-signing-2027 --minimum-refresh 720h
```

`rotate` is a workflow, not a swap: generate, overlap trust and signatures where
the format permits them, republish public material, emit user-facing re-fetch
instructions, and retire the old key. Debian keeps one active `InRelease` signer
while its stable keyring carries both identities during overlap.

Private material sits behind `KeyRef` with pluggable backends — Actions secret,
`pass`/1Password, age/SOPS in-repo, KMS, hardware token. Where the backend can
sign remotely, the engine never holds key material.

## 9. Operations

The verbs, and which part of the model each one touches:

| Command | Touches | Reversible |
|---|---|---|
| `add <repo> <artifact…>` | Blob + PackageVersion + Placement | ✅ revert |
| `adopt --sha256 <hex> --public-origin <repo> <url>` | selected bytes + origin, pinned by SHA-256 | ✅ |
| `build <product> --distro …` | repack/build → Blob + PackageVersion | ✅ |
| `promote <pv> <repo>/<track>` | Placement (add) | ✅ |
| `demote` / `yank` | Placement (remove), version stays recorded | ✅ |
| `prune <repo> --keep 5` | Placements, then blob GC | ✅ until GC |
| `check` | adopted bytes still match their pin? artifacts intact? (release watching awaits Sources) | read-only |
| `status` | committed repository evidence; live remotes deferred | read-only |
| `plan` / `apply` | writes the plan / executes exactly it | per-change |
| `verify` | container install from the staged tree | read-only |
| `render` | static status + install page | — |

Two asymmetries `plan` must display, not hide:

**Irreversibility.** `git revert` un-publishes a `.deb`. It cannot un-publish a
container tag, a PyPI upload, or an AUR push. Irreversible Changes are marked
distinctly and `apply` confirms them separately.

**Gates**, unchanged from the original design and still correct:

| Gate | Meaning | Fits |
|---|---|---|
| `auto` | apply immediately | apt, apk, your own repos |
| `pr` | open a branch + PR; merging applies | AUR, Homebrew, nix, and now lock diffs |
| `approval` | pause on a CI environment with required reviewers | dnf, OCI, anything irreversible |

A recipe target has a **diff worth reading** — a PR is the right object. A
stateless rebuild-and-deploy has no diff, and wants a deployment gate. Keeping
both, as per-repository data rather than workflow shape, is the point.

## 10. Manifest

Target schema. The workspace, repository, and key sections below are
implemented; the `[product.*]` sections — sources, requirements, and mappings —
are the design for the unbuilt Release/Mapping half of the model and gate the
status matrix (§13).

```toml
[workspace]
name = "shellcell"

[product.ttysvg]
source = { type = "github-release", repo = "shellcell/ttysvg" }
requires = [
  "openssl:dev >= 3.0",     # capability name, translated per format+distro
  "zlib",
]

  # Mapping: names, roles and per-destination overrides. Everything here is
  # defaulted by convention; only the surprises need writing down.
  [product.ttysvg.map.deb]
  main    = "ttysvg"
  doc     = "ttysvg-doc"     # would default to this anyway
  acquire = "repack"         # upstream ships a tarball; we build the .deb
  [product.ttysvg.map.pypi]
  main    = "tty-svg"        # → normalized tty_svg by PEP 503
  acquire = "adopt"          # selected wheel, our index, operator-pinned sha256
  [product.ttysvg.map.npm]
  main = "@shellcell/ttysvg"
  [product.ttysvg.map.aur]
  main = "ttysvg"
  bin  = "ttysvg-bin"

# Two repositories, one format — different hosts, keys, gates and audiences.
[repo.apt]
format  = "deb"
host    = { type = "github-pages", repo = "shellcell/packages", path = "apt" }
key     = "apt-signing"
tracks  = ["stable", "testing"]
distros = ["debian/bookworm", "debian/trixie", "ubuntu/24.04"]
arches  = ["amd64", "arm64"]      # a filter, not a coordinate: blobs declare theirs
gate    = "auto"
keep    = { versions = 5, pinned = ["0.1.0"] }

[repo.apt-internal]
format  = "deb"
host    = { type = "s3", bucket = "internal-pkgs", prefix = "apt" }
key     = "internal-signing"
tracks  = ["nightly"]
distros = ["debian/bookworm"]
gate    = "auto"
visibility = "private"

[repo.dnf]
format  = "rpm"
host    = { type = "github-pages", repo = "shellcell/packages", path = "dnf" }
key     = "rpm-signing"           # rsa4096 — cannot share apt's key if that is ed25519
distros = ["el/9", "fedora/40"]
gate    = "approval"

[repo.pypi]
format = "pypi"
host   = { type = "s3", bucket = "pkgs.shellcell.dev", prefix = "simple" }
gate   = "auto"                   # no distros: wheel tags carry the platform

[repo.charts]
format = "helm"
host   = { type = "oci", registry = "ghcr.io/shellcell" }
gate   = "approval"

# Long-tail dependency naming the built-in capability table doesn't cover.
[deps.openssl]
deb        = "libssl3"
"deb:dev"  = "libssl-dev"
rpm        = "openssl-libs"
"rpm:dev"  = "openssl-devel"
apk        = "openssl"
"apk:dev"  = "openssl-dev"

[remote.aur]
roles    = ["target", "observe"]
kind     = "aur"
gate     = "pr"
key      = "aur-ssh"
packages = ["{name}", "{name}-bin"]

[remote.nixpkgs]
roles = ["observe"]          # nothing to publish; drift detection only
kind  = "nixpkgs"
lag   = "30d"                # a nixpkgs cycle is not a failure
```

`lag` matters: version skew across destinations is **normal**. AUR lags by a
merge, nixpkgs by a cycle. Without a per-destination tolerance the matrix turns
into noise everyone learns to ignore.

## 11. Components

Everything is a shell around one library. If a capability exists only in the
server, or only in the Action, it is in the wrong place.

### 11.1 The engine

A Go module holding the domain model, the planner, and **nine driver
interfaces**. Those interfaces are also the complete answer to "what does this
thing talk to":

| Driver | Responsibility | Today / representative targets |
|---|---|---|
| **Format** | index generation, versions, names, deps | pypi, deb, helm, raw, rpm, apk (§5 tiers) |
| **Source** | watch releases, fetch bytes | pinned HTTPS fetch; watch awaits the Release model |
| **BlobStore** | content-addressed bytes | local CAS, S3-compatible; ORAS/registry later |
| **Host** | where a built tree lands | local dir, S3-compatible, GitHub Pages; rsync/registry later |
| **Forge** | review evidence for gates | github, plain git; gitlab/forgejo later |
| **Signer** | hold or use private key material | encrypted file; KMS/PKCS#11 later |
| **Remote** | foreign repositories | Phase 4: aur, homebrew, nixpkgs, npmjs, pypi, ghcr |
| **Runner** | containers for verify | docker, podman |
| **Notifier** | gate pending, verify failed, upstream lag | Phase 4 |

Nothing above the engine may know which implementation is in use. That is the
rule that keeps GitHub from quietly becoming a requirement.

**Implementation: Go**, single static binary, same artifact for CI and laptop.

**Pure-Go index generation is worth the effort.** Shelling out means
`reprepro`, `createrepo_c`, and a Docker daemon — Linux-only dependencies that
make local dry runs painful on macOS and break the purity §4 depends on. The
formats are tractable: the Debian index is nearly trivial, `repomd` is about a
day, `APKINDEX` is a tar containing a text file, PEP 503 is HTML. The same
argument extends to **signing: pure-Go OpenPGP, never shell to `gpg`** — gpg's
ambient keyring state is the single worst thing to debug in CI, and RPM header
signing and apk's RSA are both implementable directly.

### 11.2 Inventory

| # | Component | Form | Needed by |
|---|---|---|---|
| 1 | **Engine** | Go module | Phase 0 |
| 2 | **CLI** (incl. `serve`, `verify`) | static binary | Phase 0 |
| 3 | **Conformance suite** | golden trees + client containers | Phase 0 |
| 4 | **Verify matrix images** | pinned upstream refs | Phase 0 |
| 5 | **Container image** | OCI, multi-arch | Phase 2 |
| 6 | **CI integrations** | Action / CI component / Makefile | Phase 2 |
| 7 | **Git state repo** | layout convention + schema | Phase 1 |
| 8 | **Blob store** | local CAS, then external drivers | Phase 1 / 2 |
| 9 | **Public site renderer** | static generator + `status.json` | Phase 2 |
| 10 | **TUI** | same binary | Phase 3 |
| 11 | **Knowledge base** | versioned data artifact | Phase 3 |
| 12 | **`doctor`** | CLI subcommand | Phase 3 |
| 13 | **`import`** | CLI subcommand | Phase 3 |
| 14 | **Notifier** | driver | Phase 4 |
| 15 | **Server** | binary | Phase 5 |
| 16 | **Console** | SPA over the server API | Phase 5 |
| 17 | **Forge app** | GitHub App / GitLab app | Phase 5 |
| 18 | **Format plugin SDK** | stdio protocol + example | Phase 5 |
| 19 | **Docs site** | static | ongoing |

Four of those are not obvious and are worth their own justification:

**3 — the conformance suite is what makes "Tier 1" mean anything.** Golden
output trees per format catch regressions in generation; real client containers
catch the things golden files can't. Without it, tiering is marketing.

**12 — `snailmail doctor <url>`** points at *any* repository, yours or not,
fetches the index, validates it, and reports the classic traps: an unreadable
signing algorithm, an expired key, a `Packages` file listing pool paths that
404, a `repomd.xml` whose checksums don't match. It needs no manifest, no
config, and no adoption — which makes it the one component that is useful to
someone who has never heard of snailmail, and therefore the best entry point
the project has.

**13 — `import`** adopts an existing reprepro/aptly/createrepo site into a
manifest and lock. Nobody starts from zero; without this, every existing repo
owner faces a migration they have no reason to attempt.

**11 — the knowledge base** (dependency capability table §3.7, key
compatibility table §8, distro release metadata, verify image pins) is **data
with its own release cadence**, versioned and shipped separately from the
binary. `libssl-dev` moving to `libssl3-dev` in some future Debian must be a
data update, not a release. Arguably the most valuable single asset here.

### 11.3 The git state repo

```
  snailmail.toml              manifest — repositories, remotes, products, mappings
  repos/apt.lock.toml         placements: the contents of each repository
  repos/pypi.lock.toml
  keys/*.pub                  public key material, every form each format needs
  .forge/…                    generated CI workflows
  docs/install-*.md           generated install instructions
```

Not in it: blobs, the built index, private keys.

**One repo or two?** Default **one**: `main` holds state, the published tree
goes to a `pages` branch or a bucket. Two is for when state must be private
while repositories are public, or when repositories span organizations.

**Federation.** The matrix's value comes from centralization; org reality is
per-team repos. The manifest may therefore reference locks living in *other*
repositories, and `status` aggregates across them. Centralized by default,
federated when it has to be — but note that a federated workspace loses atomic
cross-repository plans, and that trade should be made deliberately.

### 11.4 Forge-agnostic by construction

GitHub is a driver, not a foundation. GitLab, Forgejo/Gitea and plain git are
first-class.

| Capability | GitHub | GitLab | Forgejo / Gitea | Plain git |
|---|---|---|---|---|
| Review gate | Pull Request | Merge Request | Pull Request | — (`auto`/local approval) |
| CI | Actions | GitLab CI | Forgejo Actions (Actions-compatible) | external |
| Static host | Pages | Pages | Pages | rsync / S3 |
| Blob store | Releases, ghcr | Releases, Generic Packages, registry | Releases, Packages | S3 / local |
| Approval gate | Environments | protected env / manual job | manual job | interactive confirm |
| Secrets | Actions secrets | CI variables | Actions secrets | env / signer backend |
| OIDC to cloud | ✅ | ✅ | partial | — |

Two things fall out that are easy to miss:

**GitLab and Forgejo ship native package registries** — deb, rpm, npm, PyPI,
Helm, containers. That makes them simultaneously a **Host** (publish into their
registry instead of generating a tree) and a **Remote** (observe or push).
Self-hosters get a supported path that GitHub simply does not offer.

**Plain git must work.** No forge, no CI, no PRs: `auto` gates, an interactive
confirm for `approval`, rsync or S3 hosting, cron for `check`. If that mode is
broken, the abstraction is decorative — so it is a tested topology, not a
theoretical one.

The wizard detects the forge from the git remote and never asks unless it
cannot tell.

### 11.5 Automation: the container image is the integration point

The primary automation artifact is **a multi-arch OCI image containing the
CLI**. Everything else wraps it:

```
  ghcr.io/shellcell/snailmail:v1
        ├── GitHub Action        (thin wrapper, also works on Forgejo Actions)
        ├── GitLab CI component  (include: template)
        ├── Woodpecker / Drone   (plain image, no wrapper needed)
        └── Makefile / justfile  (for everything else, and for laptops)
```

Building it this way means a new CI system costs a template, not a port. A
per-forge Action that reimplements logic is how tools acquire four subtly
different behaviours; the wrapper must contain *no* logic beyond argument
passing.

### 11.6 Two webs, not one

The public page is `snailmail render`: static files, no infrastructure — the
status matrix, generated install instructions, key fingerprints, and a
`status.json` for badges. Install instructions generated from what was actually
built and verified (§7) retire the hand-maintained page that advertises
packages the repo does not serve.

A management console is Phase 5, exists only with the server, and is bound by
one rule: **it is a strict view over the engine** — every button is a CLI
command with `--json`, and nothing may be doable only through the console.

### 11.7 Topologies

The same engine, lock format, and output tree in all five. Moving between them
is a config change, never a migration — that property is worth more than any
individual feature and should be defended in tests.

| | Solo | Forge-native | CI-agnostic | Server | Hybrid |
|---|---|---|---|---|---|
| State | local git | forge repo | any git | forge repo | forge repo |
| Blobs | local | forge releases / registry | S3 | S3 | S3 |
| Host | local dir | Pages | S3 + CDN | server | CDN + server for writes |
| Gates | interactive | PR / environment | PR | console | console |
| Writes | CLI | CLI in CI | CLI in CI | native protocols | native protocols |
| Servers | 0 | 0 | 0 | 1 | 1 |

**Forge-native is the flagship** — zero servers, works on GitHub, GitLab or a
self-hosted Forgejo. **Hybrid is the production shape**: a server for
authenticated writes, static objects behind a CDN for reads, so read traffic
never touches it.

### 11.8 The minimum viable set

Seven components, and the project is genuinely useful:

> engine · CLI · conformance suite · container image · CI integration ·
> git state repo · public site renderer

Foreign adapters and notifications are Phase 4; the server, console, forge app,
attestations, and plugins are Phase 5 and must stay optional. **Dogfood it**:
snailmail publishes snailmail, through
snailmail, which is both the credibility argument and the best available test.

## 12. What it connects to

### 12.1 Outbound

| Purpose | Talks to |
|---|---|
| Watch releases | forge APIs, git ls-remote, HTTP |
| Fetch artifacts | forge releases, arbitrary HTTPS, upstream package repos |
| Store blobs | OCI registries (ORAS), S3-compatible, GCS, Azure |
| Publish trees | forge Pages (git push + API), S3/R2, rsync/ssh, OCI registries |
| Observe remotes | crates.io, PyPI JSON, npm registry, formulae.brew.sh, AUR RPC, nixpkgs, repology |
| Publish to remotes | AUR over ssh, forge APIs (PRs), npm/PyPI/crates upload, registry push |
| Sign | KMS, Vault, PKCS#11, or local key material |
| Verify | container registries — pulls the distro matrix |
| Notify | forge issues, Slack, webhooks, SMTP |

**Observation must prefer JSON APIs over parsing native languages.** A Homebrew
formula is Ruby and a nixpkgs derivation is Nix; evaluating either to answer
"what version is published?" is absurd. `formulae.brew.sh` and the nixpkgs
channel index both serve JSON. Parse the language only when there is no API,
and treat that as a known-fragile path.

### 12.2 Local dependencies

| Tool | Needed for | Required? |
|---|---|---|
| `git` | state repo operations | yes (universally present in CI) |
| `docker`/`podman` | `verify`, sandboxed builds | only for `verify` |
| `nfpm` | `repack` | only for `repack` (vendored) |
| `makepkg`, `namcap`, `brew audit` | AUR/tap validation | only for those remotes, **in a container** |
| `ssh` | AUR push | only for AUR |
| `cosign` | OCI signing | only for OCI |
| `gpg`, `rpm`, `abuild`, `reprepro`, `createrepo_c` | — | **never** — pure Go (§11.1) |

The floor is: **the binary and `git`.** Everything else gates a specific
feature and degrades to a clear error naming what is missing, never a stack
trace.

### 12.3 Credentials

| Credential | Scope | Blast radius if leaked |
|---|---|---|
| Forge token | the state repo + target repos | write to your repos |
| Cloud credentials | one bucket/prefix | overwrite a repository |
| Registry token | one namespace | poison images |
| Remote publish tokens (npm, PyPI, AUR) | one package namespace | **publish as you, irreversibly** |
| Signing key | a repository's trust | forge packages your users install |

Two rules. **Prefer OIDC federation to long-lived keys** wherever the forge
supports it — GitHub and GitLab both do, which removes the cloud credential
entirely. **Never require a broadly-scoped personal token**; if an operation
needs org-wide access, that is what the forge app (component 17) is for, and
until it exists the operation is manual.

The signing key is the one that matters. §8's signer backends exist so that
with KMS or a hardware token the engine never holds it — and the fact that adopting
selected third-party bytes (§3.8) means signing them with that key is precisely why it
deserves this much care.

### 12.4 Rate limits and failure modes

- **Container registry pulls for `verify` are the real constraint.** A matrix of
  six distros times four products, on every plan, hits Docker Hub's anonymous
  limits immediately. Pin to authenticated ghcr/quay mirrors and cache layers in
  CI; treat a pull failure as infrastructure, not a verify failure.
- **Observation is N remotes × M products remote reads** for one `status` —
  cache with a short TTL, and make it explicit when a figure is cached.
- **Forge API limits** bound how many PRs and status reads a rollout can do.
- **Everything remote fails.** Partial observation must render as "unknown", a
  visibly different state from "missing" — conflating them is what trains people
  to ignore the matrix.

### 12.5 Extensibility

Tier 1/2 formats compile in. Third-party formats are external binaries named
`snailmail-format-<name>` speaking a small JSON protocol over stdio — the
git-remote-helper pattern. Language-agnostic, no plugin ABI, trivially testable.
The same pattern is available for Host and Notifier, which are the other two
places where the long tail is genuinely unbounded.

## 13. Interfaces

**The CLI is the product.** `--json` on everything, so CI is the CLI in a
container. The TUI and web page are views over the same engine.

**The headline view is the matrix** — Products × destinations — served today
by `status --json` and the rendered page, and later by a TUI over the same
engine:

```
              apt      dnf      apk      aur      aur-bin  brew     nixpkgs
  ttysvg      0.1.2    0.1.2 ✗  0.1.2    0.1.2    0.1.2    0.1.2    0.0.7 ⚠
  exex        0.3.2    0.3.2 ✗  0.3.2    0.3.2    0.3.2    0.3.2    —
  cnvrt       0.0.3    0.0.3 ✗  0.0.3    0.0.3    0.0.3    0.0.3    —
  snailrace   0.0.5    0.0.5 ✗  0.0.5    0.0.5    PR #12   0.0.5    —

  ✗ verify failing   ⚠ lagging   PR # gate pending
```

One screen answering a question that currently costs four repos and three CI
tabs, with pending gates as visible as failing repositories. Filling the
version cells requires the Release model (§3.1); until then status reports
committed placements, binding completeness, and deployment receipts.

**Web, read-only**: `snailmail render` emits the same matrix as a static page
beside the repositories, with badges and generated install instructions. No
server, no auth, no database.

**Server, optional.** Static hosting covers reads; it cannot cover *writes* —
`npm publish`, `twine upload`, `docker push`, `helm push`, `cargo publish` are
authenticated HTTP APIs. That, plus private repositories and pull-through
mirroring, is its entire justification. The constraint that keeps it from
becoming a second system:

> **The server is a git-writing gateway, not a database.**

```
  npm publish ─▶ snailmail server ─┬─▶ blob store  (bytes)
                                   ├─▶ git commit  (lock edit)
                                   └─▶ rebuild + sync
```

Every mutation — CLI, CI, web UI, `npm publish` — becomes the same lock commit.
One state model, one audit log, one rollback mechanism. Run the server and the
repositories keep working exactly as they did static, because the output is
still a tree. Write rates where per-publish commits are absurd are out of scope
until proven real; any escape hatch costs the revert story and needs its own
design first.

```
snailmail init | setup <format>     # wizard; every prompt is also a flag
snailmail add | adopt | promote | yank | prune
snailmail check | status | doctor <url>
snailmail plan | approve | apply | verify
snailmail keys new|publish|audit|rotate
snailmail approval-key | blob-store | render | serve
```

Planned: `import <url>` (adopt an existing repository into a manifest), `ui`,
`server`. Every command that reports a result accepts `--json`.

## 14. Phases

Ordered so the pure, testable core comes first and the irreversible parts last.

**Phase 0 — the pure core.** `Format` for **pypi, deb, helm**, plus `serve` and
`verify`. No manifest, no hosting, no keys: a library and three commands that
turn a directory of files into a correct, locally-servable repository. These
three because pypi is trivially correct, deb is the hard one worth learning
early, and helm proves the shape generalizes.

**Phase 1 — Git-backed local reconciliation.** Add the model of §3, manifests,
locks, local CAS, publication ledgers, `setup`, `add`, and exact `plan`/`apply`.
The phase is complete when a reviewed Git state can stage, verify,
conditionally switch, recover, and roll back a local managed release without
weakening immutable publication bindings. Richer placement mutations remain
operational breadth rather than a prerequisite for safe reconciliation.

**Phase 2 — owned hosting.** Generalize publication behind a provider-neutral
host contract. Public S3-compatible PyPI is the first remote slice. Complete
the phase with scoped private S3 reads, shared remote blob storage, public
GitHub Pages, `auto`/`pr`/`approval` gates, generated install and status pages,
and containerized CI distribution. The private five-minute target uses
authenticated object storage or a CDN, not GitHub Pages.

Status: implemented as specified, for the PyPI remote-host scope. `README.md`
records the exact surface.

**Phase 3 — signing, operations, and breadth.** Add explicit signer effects,
key backends, the compatibility table, and `keys new|publish|audit|rotate`;
then `promote`, `yank`, `prune`, `check`, `status`, `doctor`, `import`/`adopt`,
the TUI, and the versioned knowledge bundle. Expand Tier 1 deliberately: rpm
and apk first, followed by nix cache, cargo, go, and maven. Name mapping and
dependency translation arrive only with formats that prove those abstractions
are needed.

Status: the signing and operations slices are implemented — encrypted
file-backed RSA4096 keys with committed public forms, the versioned signing
compatibility table, `keys new|publish|audit|rotate` with receipt-backed Debian
rotation, plan-resolved deterministic signatures verified through apt
`signed-by`, and `promote`/`yank`/`prune`/`check`/`status`/`doctor`/`adopt`.
`README.md` records the exact surface.

The format-and-host coupling that this phase owed is now closed for its first
cases: GitHub Pages serves signed Debian and raw alongside PyPI, and `raw`
publishes artifacts that carry no ecosystem metadata. The matrix itself is
declared in `host/support.go` rather than inferred, so the gaps that remain are
readable rather than discovered. Remaining: S3 beyond PyPI, additional key
backends, `import`, and the TUI.

A Pages repository needs a companion preview site only where a gate waits for a
human to review one. Under an `auto` gate the preview is optional, and its
absence is a stated trade: the staged tree is still verified by a real client,
but against the tree itself rather than against a served endpoint, so nothing
checks that the host serves it correctly until it is live.

**Phase 4 — foreign remotes.** Implement `observe` roles first for read-only
drift detection, then irreversible `target` operations for AUR, Homebrew,
nixpkgs, ghcr, and npmjs/PyPI uploads. Every target uses explicit gates,
version-binding ledgers, live preconditions, and optional notifications.

**Phase 5 — optional control plane and extensions.** Add the server, management
console, forge apps, attestations, and the versioned process-plugin protocol
only if Phases 1–4 are being used. Static reads remain independent of the
control plane. A great static tool beats a mediocre hosted one.

Each phase is useful alone. If Phases 1–3 are enough, stop: most of the present
pain is visibility, policy, and setup, not mechanics.

## 15. Things that will bite

- **Scope explosion.** 13 formats × 7 hosts × 3 gates is not a product, it is a
  matrix nobody can test. Tiering is the defense, and it only works if Tier 1 is
  defended ruthlessly.
- **GitHub Pages limits are real**: ~1 GB per site, 100 GB/month bandwidth, 10
  builds/hour. A package repository hits these. Warn at 70%, and say it in the
  `setup` wizard rather than let someone find out at 900 MB.
- **`gh-pages` history bloat.** Committing `pool/` grows the branch forever.
  Deploy as an orphan commit and force-push, and document that the branch is
  not a history.
- **Index rebuild cost.** Full regeneration is O(packages) — fine to ~10k,
  painful beyond. Incremental generation is the escape hatch; don't build it
  before something is measurably slow.
- **The lock as a text file** does not obviously survive 10k placements.
- **The distro matrix multiplies everything.** 4 products × 3 tracks × 6 distros
  × 2 arches is 144 cells before you have shipped anything twice. Storage, CI
  time, verify containers and the TUI all scale with it. Default to the
  narrowest matrix that works and make widening deliberate.
- **Adopting selected bytes means signing them.** Your repository signature
  endorses an artifact you did not build without proving its source is authoritative. That is often the
  right trade, but it must be a visible choice in `plan`, not a default nobody
  noticed.
- **Cross-distro dependency naming has no complete answer.** The capability
  table will always have edges; the design leans on `verify` for correctness
  rather than pretending otherwise. If that backstop is ever weakened, the whole
  dependency story collapses quietly.
- **Honest competition.** `aptly`, `pulp`, `artipie`, Cloudsmith and JFrog all
  exist. The unoccupied ground is: *one tool, many formats, static output, git
  as the state, wizard-to-working in five minutes, and a signing compatibility
  table that catches the errors everyone else lets you make.* Build those;
  borrow the rest.

## 16. Open questions

Resolved since the first draft: the capability table is vendored as a versioned
knowledge bundle, digest-pinned in every plan; and the tool is a library
(`engine`) with a thin CLI, as the server will require. Still open:

- **Does the lock shard?** 10k placements is a 40k-line TOML and a miserable
  diff. Per-track files? Per-package? A `.jsonl` that diffs well?
- **Is `raw` too good?** If the escape hatch is comfortable enough, nobody uses
  the typed formats and the model stops earning its keep.
- **Does `setup` write CI or print it?** Writing is friendlier; printing doesn't
  fight whatever the repository already does. Leaning: write, but only into a
  file the tool owns entirely.
- **Rollout: real object or derived view?** Deriving it from Placements is
  cheaper and can't go stale; storing it allows "0.1.2 was released on ‹date›,
  approved by ‹person›" as a fact rather than an inference.
- **Is `adopt` at scale just mirroring?** Adopting a handful of upstream
  artifacts and running a pull-through cache of all of PyPI differ in degree,
  not in kind. The model already supports the first. Deciding where the line
  falls determines whether §16's mirroring question is a feature or a product.
- **Does `repack` belong here at all?** It is the one place snailmail would
  *build* rather than *arrange*, which is a different job with a different
  failure surface. `nfpm` does it well; the question is whether snailmail drives
  it or merely consumes its output.
- **Full upstream mirroring** (a pull-through cache of PyPI or Debian) is large,
  adjacent, and commonly wanted. Is it a separate product rather than a phase?
- **Where does snailmail's own manifest live?** Its own repo with a published
  action, or vendored into the packages repo? Leaning own repo: the manifest
  sits above any one repository.
