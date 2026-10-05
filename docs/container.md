# Container

The supported production shape for `epistle` is a rootless Podman or Docker
container driven by `podup`. The image is built from the same source as the
`.deb`, with the same musl target and the same pinned toolchain; the .deb and
the image always agree on what is running.

## What the image contains

The base is `gcr.io/distroless/static-debian12:nonroot`, pinned by digest
in the `Containerfile`. The image carries the musl-statically linked
release binary, the runtime data the binary needs, and nothing else.
The inventory below was produced by `podman create` of `epistle:test`
followed by `podman export | tar -t`, on this host with
`podman 5.7.0`, on 2026-10-04.

- `/usr/bin/epistle`, the binary. Built with the same
  `cargo build --release --locked --target <musl>` invocation the .deb
  build uses, so the .deb and the image always agree on what is running.
- A `/etc/epistle` directory owned by `uid:gid 65532:65532`, created at
  build time. The operator's `mail.toml` is bind-mounted over it; no
  file inside the image ever needs to be writable.
- `/etc/ssl/certs/ca-certificates.crt` (224 449 bytes), the merged CA
  bundle. The binary uses rustls with the system trust store, so the
  bundle is what verifies outbound TLS for SMTP submission, IMAP
  retrieval, ACME, and any other connection that pins a public CA.
- `/etc/passwd` and `/etc/group` with three entries: `root`,
  `nobody`, and `nonroot` (uid 65532, gid 65532, home `/home/nonroot`,
  shell `/sbin/nologin`). The image sets `USER 65532:65532`, so the
  binary runs as `nonroot`. The other two entries are not used; they
  are in the base.
- `/usr/share/zoneinfo/` and the tzdata package metadata under
  `/usr/share/doc/tzdata/`. The binary is single-timezone (the host's
  `TZ`), so tzdata is not exercised at runtime; it is in the base.
- No shell, no package manager, no `openssl`, no `libc` (musl is
  statically linked into the binary), no `ca-certificates` source
  tools, no editor. Anything that would have called `sh -c` is
  not in the image; that is also why `epistle dkim-keygen --rsa`
  has to be run on the host.
- OCI labels: `org.opencontainers.image.source`,
  `org.opencontainers.image.version`, `org.opencontainers.image.revision`,
  and `io.containers.autoupdate=registry` so `podman-auto-update(1)`
  can track the `<version>` tag.

The image is 28 MiB on `linux/amd64`. `USER 65532:65532`; `ENTRYPOINT
["/usr/bin/epistle"]`; `CMD ["serve", "--config", "/etc/epistle/mail.toml"]`.

## What is meant to run inside the image

`epistle serve` and only `epistle serve`. Every other subcommand is either a
one-shot operator action or a developer tool and is documented as running on
the host, not in the container. Two deserve calling out:

- `epistle dkim-keygen --rsa` shells out to `openssl genpkey`. The distroless
  base ships no `openssl`, so the RSA DKIM key is generated on the host and
  bind-mounted into the data directory as the configured `rsa_key_file`. The
  Ed25519 selector (`epistle dkim-keygen`, no flag) is fine in either place
  because it does not shell out.
- `epistle init` is an interactive setup wizard meant to be run on the host
  once, then re-run only for structural changes (a second account, a new
  domain). It writes `/etc/epistle/mail.toml`, which is then bind-mounted
  into the container.

Anything else that is not `serve` (queue, reports, export, import, backup,
verify, mta-sts-serve, the various `*-keygen`) is documented to run on the
host with the same data directory, the same config file, and the same
`glyndor-epistle` account that the container would have used.

## Running it

The minimum a Podman or Docker compose unit needs is:

```sh
podman run --rm \
  --name epistle \
  --userns=keep-id:uid=65532,gid=65532 \
  -p 25:25 -p 465:465 -p 587:587 \
  -p 143:143 -p 993:993 -p 995:995 \
  -p 8080:8080 \
  -v /etc/glyndor/epistle:/etc/epistle:ro \
  -v /var/lib/glyndor/epistle:/var/lib/glyndor/epistle \
  ghcr.io/glyndor/epistle:0.8.0
```

The `/etc/glyndor/epistle` mount carries `mail.toml`; the
`/var/lib/glyndor/epistle` mount carries the on-disk mail store. Both are
created and owned by the `glyndor-epistle` account the `.deb` postinst sets
up (`debian/epistle.postinst`); running the container under that same uid is
what the existing rootless Podman stack under `podup` does.

### Why `--userns=keep-id` is load-bearing

`USER 65532:65532` inside the image and rootless Podman outside it do not
match by default. Without a userns mapping the container's `uid 65532` is
mapped to a subordinate uid in the operator's range (the first unused
slot, typically `100000`), and a host file owned by `glyndor-epistle`
with mode `0600` is unreadable. The default command prints:

```text
error: cannot read config file /etc/epistle/mail.toml: Permission denied (os error 13)
```

`--userns=keep-id:uid=65532,gid=65532` rewrites the container's `uid 65532`
to the operator's uid on the host, so the bind-mounted `mail.toml` is
readable and the binary reaches the parser instead of a permission error.
The compose form is the same flag under the `userns_mode:` key:

```yaml
services:
  epistle:
    image: ghcr.io/glyndor/epistle:0.8.0
    userns_mode: "keep-id:uid=65532,gid=65532"
    volumes:
      - /etc/glyndor/epistle:/etc/epistle:ro
      - /var/lib/glyndor/epistle:/var/lib/glyndor/epistle
```

Both the failing default and the working mapping were checked on this
host: a host directory with a `0600` file owned by the operator, mounted
into the image with no userns flag, returned `Permission denied (os
error 13)`. The same mount with `--userns=keep-id:uid=65532,gid=65532`
let `config-check --config /etc/epistle/mail.toml` print
`configuration is valid` and exit 0.

## Tags

The release job pushes per-arch images plus a multi-arch manifest list with
three floating tags:

- `ghcr.io/glyndor/epistle:0.8.0-amd64`, `…:0.8.0-arm64` per-arch, built
  natively on the matching runner.
- `ghcr.io/glyndor/epistle:0.8.0` the full release.
- `ghcr.io/glyndor/epistle:0.8` the latest patch release in the `0.8` line.
- `ghcr.io/glyndor/epistle:0` the latest minor release in the `0.x` line.

`podman pull ghcr.io/glyndor/epistle:0.8` keeps getting patches;
`…:0` keeps getting minors. A consumer that wants to pin a specific build
uses `gh attestation verify oci://ghcr.io/glyndor/epistle:0.8.0 …` (below);
that command resolves the tag itself, so a separate digest lookup is
not needed. `podman pull --quiet` only prints the local image id and is
not a digest, so it has no place in the verification path.

## Verifying the build provenance

The release job signs the multi-arch manifest list with GitHub's OIDC-backed
Sigstore. The signed envelope is published as a GitHub attestation, so a
consumer does not need a separate signer key:

```sh
gh attestation verify oci://ghcr.io/glyndor/epistle:0.8.0 \
  --repo Glyndor/epistle \
  --signer-workflow Glyndor/epistle/.github/workflows/release.yml \
  --deny-self-hosted-runners
```

A green `Verification succeeded` line proves four things and only four
things:

1. An attestation exists in `Glyndor/epistle` for the manifest list
   that resolves from `oci://ghcr.io/glyndor/epistle:0.8.0`.
2. The signer workflow is `Glyndor/epistle/.github/workflows/release.yml`,
   identified by the `SubjectAlternativeName` of the Sigstore-issued
   certificate. Not just any workflow in this repository -- specifically
   the release workflow.
3. The signer was a GitHub-hosted runner, not a self-hosted one. A
   self-hosted runner under the attacker's control could mint a key
   the Sigstore CA would still sign, so `--deny-self-hosted-runners`
   refuses the verification rather than passing it.
4. The attestation's predicate is `https://slsa.dev/provenance/v1`,
   the SLSA build provenance shape the action produces.

A pass does not prove:

- The list's bytes are what the consumer will pull. The attestation
  is bound to the manifest list's digest, not to the tag, and a
  digest-pinned reference (`oci://ghcr.io/glyndor/epistle@sha256:...`)
  is the only way to make sure the consumer pulls the same bytes
  the attestation was produced for. The tag form is convenient for
  upgrades; it is not a content-addressed handle.
- The build inputs were not tampered with on a self-hosted runner
  in some other repository. The repository and workflow are pinned;
  the runner type is GitHub-hosted; the build itself is out of scope.

The same `gh attestation verify` form works for any of the three
floating tags and for a digest-pinned
`oci://ghcr.io/glyndor/epistle@sha256:...` reference; the digest form
is what podup's update path uses.

## How the image is built and published

`Containerfile` and `.containerignore` at the repository root. The build is
exercised on every pull request that touches `Containerfile`, `.containerignore`,
`Cargo.toml`, `Cargo.lock`, `src/**`, `.sqlx/**` or the workflow file
itself, by `.github/workflows/container.yml`. The release-time publish is
appended to `.github/workflows/release.yml`; it is gated on the repository
variable `EPISTLE_PUBLISH_IMAGE == 'true'` and does nothing until the owner
turns the switch on, so a tag still cuts even if the image never ships.
