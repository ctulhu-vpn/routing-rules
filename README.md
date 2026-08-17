# Ctulhu VPN Routing Rules

This repository builds versioned client-routing artifacts for Ctulhu VPN. It
combines a commit-pinned snapshot of
[`1andrevich/Re-filter-lists`](https://github.com/1andrevich/Re-filter-lists)
with small, reviewed Ctulhu overlays.

The repository is the successor of `ctulhu-vpn/ru-proxy-pac`. PAC remains a
legacy output; Shadowrocket rule sets/modules and Mihomo MRS providers are the
primary artifacts.

## Invariants

- Upstream content is fetched only from the exact SHA in
  [`upstream.lock.json`](upstream.lock.json).
- Proxy inputs may contain only domain and public IP/CIDR records.
- Domain records are suffix rules: the base domain and all of its subdomains
  must match consistently in every generated client format.
- Ctulhu direct exceptions take priority over matching proxy records.
- `ipsum.lst` is intentionally excluded from the default profile because broad
  shared-CDN networks can proxy unrelated traffic.
- A failed fetch, validation, build, or publication must not replace the last
  known-good release.
- Outputs never contain subscribe tokens, VPN credentials, scripts, rewrite
  directives, or TLS MITM configuration.

## Inputs

```text
vendor/refilter/                 pinned upstream snapshot
rules/ctulhu/proxy-domains.txt  Ctulhu proxy-domain additions
rules/ctulhu/proxy-ipcidr.txt   Ctulhu proxy-network additions
rules/ctulhu/direct-domains.txt reviewed direct exceptions
rules/ctulhu/direct-ipcidr.txt  local/private and reviewed direct networks
```

Run `npm run update-upstream` to resolve current Re:filter `main`, validate all
configured inputs, update their hashes, and rewrite the pinned vendor snapshot.
Use `npm run update-upstream -- --commit=<40-hex-sha>` for an explicit commit.
Every update must be reviewed as a normal pull request.

## Build

Requirements: Node.js 24 and npm 11.

```sh
npm install
npm run setup:mihomo
npm run check
```

`setup:mihomo` downloads the platform-specific binary pinned in
[`toolchain.lock.json`](toolchain.lock.json), verifies its SHA-256, and installs
it under ignored `tools/`. The build does not use an unpinned system converter.

Set the public module origin for a production release:

```sh
ROUTING_RULES_PUBLIC_BASE_URL=https://hub.example.invalid/routing-rules/v1 npm run build
```

The `.invalid` default is deliberately safe for local builds. Release CI must
set the real HTTPS `/routing-rules/v1` URL.

## Outputs

`npm run build` recreates `dist/v1`:

```text
dist/v1/
  manifest.json
  licenses/
  mihomo/
    direct-domains.mrs
    direct-ipcidr.mrs
    domains.mrs
    ipcidr.mrs
  shadowrocket/
    ctulhu-smart.sgmodule
    direct-domains.list
    direct-ipcidr.list
    domains.list
    ipcidr.list
  pac/proxy.pac
```

`manifest.json` records the exact routing-rules source SHA for CI builds, the
upstream SHA, input counts, pinned Mihomo version, artifact sizes, and SHA-256
digests. Generated artifacts are ignored by Git and published from CI as an
immutable release.

## Automatic publication

Every successful push to `main` performs the complete production publication:

1. validate, build, and test the exact commit;
2. create or verify the immutable prerelease `main-<40-hex-commit>`;
3. start the `ctulhu-vpn/hub` production rollout;
4. wait for its external HTTPS verification, atomic stable-alias switch, and
   final result.

The source workflow stays red if the Hub rollout fails or rolls back, so a
green `main` publication means that the stable client URL was verified. A
`v*` tag may still create a human-friendly milestone release, but it is not
required for normal rule publication.

The archive is packed deterministically, and `manifest.source.commit` equals
the commit in its automatic release id. A retry can therefore verify exact
archive equality instead of replacing an existing asset.

Repository configuration:

- Actions variable `ROUTING_RULES_PUBLIC_BASE_URL` is the credential-free
  production HTTPS URL ending in `/routing-rules/v1`;
- Actions secret `HUB_WORKFLOW_TOKEN` is a fine-grained token limited to the
  `ctulhu-vpn/hub` repository with Actions read/write access.

The token can start and observe only the Hub workflow. Production filesystem
access, public-origin settings, environment approval, verification, activation,
and rollback remain owned by the Hub repository and its `production`
Environment.

## Publication contract

Clients use stable public paths under `/routing-rules/v1/...`; they must never
reference mutable GitHub `main` or `releases/latest`. Publication order is:

1. validate and build;
2. publish an immutable snapshot;
3. verify every artifact through external HTTPS;
4. atomically switch the stable alias;
5. preserve the previous snapshot for rollback.

If automatic deployment must be repeated, run the Hub `Deploy routing rules`
workflow with the already published `main-<commit>` release id. Re-running the
source workflow verifies that an existing release contains byte-identical
content and never overwrites it.

The upstream snapshot is distributed under its MIT license, copied at
[`vendor/refilter/LICENSE`](vendor/refilter/LICENSE). Ctulhu source and outputs
remain under this repository's MIT license.
