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

`manifest.json` records the upstream SHA, input counts, pinned Mihomo version,
artifact sizes, and SHA-256 digests. Generated artifacts are ignored by Git and
published from CI as an immutable release.

## Publication contract

Clients use stable public paths under `/routing-rules/v1/...`; they must never
reference mutable GitHub `main` or `releases/latest`. Publication order is:

1. validate and build;
2. publish an immutable snapshot;
3. verify every artifact through external HTTPS;
4. atomically switch the stable alias;
5. preserve the previous snapshot for rollback.

The upstream snapshot is distributed under its MIT license, copied at
[`vendor/refilter/LICENSE`](vendor/refilter/LICENSE). Ctulhu source and outputs
remain under this repository's MIT license.
