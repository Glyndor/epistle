# Two stages: a Rust 1.98 musl build, and a distroless-static runtime
# that carries only the resulting binary, a /etc/epistle/ mount point
# and the `65532:65532` (nonroot) user. The build environment matches
# what release.yml's `build-deb` job does: the same digest-pinned rust
# image, the same musl target mapping, the same `--locked` build with
# the committed .sqlx cache. Pushing from a build that did not match
# the .deb build would reintroduce the glibc floor that the .deb path
# was changed to remove.
#
# `podman build --platform=linux/amd64` and `--platform=linux/arm64`
# cross-build the same Containerfile: `TARGETARCH` is one of `amd64` or
# `arm64` per OCI conventions, and the musl target is selected from
# it. The two values are 1:1; a request for any other arch fails in
# the case statement.

FROM docker.io/library/rust@sha256:fb4b2f1dc68c06f46618948b09d0ade147e6d2b11a6581e599b0c808d5b8a167 AS builder
# 1.98-slim-trixie. Same pin as release.yml.

ARG TARGETARCH

# musl-tools provides musl-gcc, which `ring` needs to compile its C
# against a musl target. It is not a Rust dependency, so it cannot be
# declared in Cargo.toml and has to be installed here.
RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends musl-tools ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Pick the musl target the .deb path builds for on the same arch.
# `release.yml`'s `build-deb` job carries the same mapping; keep
# these two in sync.
RUN case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-musl ;; \
      arm64) target=aarch64-unknown-linux-musl ;; \
      *) echo "no musl target mapped for TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
    esac \
    && rustup target add "$target" \
    && rustc --print target-libdir --target "$target" >/dev/null \
    && echo "$target" > /tmp/rust_target

WORKDIR /build

# Copy the build inputs. The committed .sqlx cache is the only sqlx
# data the build reads (queries are checked against it under
# `SQLX_OFFLINE=true`), so the build needs no database and no network
# to reach one. The .deb path does the same.
COPY Cargo.toml Cargo.lock ./
COPY .sqlx ./.sqlx/
COPY migrations ./migrations
COPY src ./src
COPY benches ./benches

# `--locked` rejects a Cargo.lock that has drifted from Cargo.toml;
# the same protection release.yml relies on. The binary lands under a
# target-named subdir of target/, so stage it under a fixed path the
# runtime stage can COPY without shell logic in the COPY itself.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    target=$(cat /tmp/rust_target) && \
    SQLX_OFFLINE=true \
      cargo build --release --locked --target "$target" --bin epistle \
    && install -m 0755 "target/$target/release/epistle" /epistle

# The nonroot distroless base ships no shell and no /etc/epistle.
# /etc/epistle is the conventional mount point for the operator's
# mail.toml, so create it here. The user comes from the `nonroot`
# tag: uid:gid 65532:65532. Resolved 2026-10-05 00:45:23 UTC on this
# host with:
#   podman pull gcr.io/distroless/static-debian12:nonroot
#   podman image inspect --format '{{.Digest}}' gcr.io/distroless/static-debian12:nonroot
# Bump the digest deliberately, the way db.yml documents the postgres
# digests.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:52dcfbabb7457ea47c82f6e13af8c8a4a1d9f7b0145142b3ecab20f2b888411d

# OCI labels. `--label=...` on the `podman build` command line
# overrides them at build time, so a release job can stamp the
# actual git revision without editing the Containerfile.
ARG VERSION=0.0.0
ARG REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/Glyndor/epistle"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.revision="${REVISION}"
# `registry` tells podman-auto-update(1) to look up the latest tag
# from the registry and re-pull when it changes. The release job
# tags the image with `<version>-<arch>` plus floating `<major>`,
# `<major.minor>` and `<version>` tags, so the update path is the
# `<version>` tag and not the per-arch one.
LABEL io.containers.autoupdate="registry"

COPY --from=builder /epistle /usr/bin/epistle

# `WORKDIR` creates the directory if it does not exist, so the
# operator's `mail.toml` can be bind-mounted at /etc/epistle
# read-only at run time.
USER 65532:65532
WORKDIR /etc/epistle

ENTRYPOINT ["/usr/bin/epistle"]
CMD ["serve", "--config", "/etc/epistle/mail.toml"]
