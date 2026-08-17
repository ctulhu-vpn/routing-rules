import { createHash } from "node:crypto"
import { mkdir, readFile, rm, stat, writeFile } from "node:fs/promises"
import { isIP } from "node:net"
import { dirname, join, relative } from "node:path"
import { domainToASCII } from "node:url"

const COMMENT_PREFIXES = ["#", ";"]
const FORBIDDEN_DIRECTIVES =
  /(?:^\[?(?:script|mitm|rewrite|url-rewrite)\]?(?:,|$)|javascript:|:\/\/)/i

const FORBIDDEN_IPV4 = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
]

const FORBIDDEN_IPV6 = [
  ["::", 128],
  ["::1", 128],
  ["::ffff:0:0", 96],
  ["2001:db8::", 32],
  ["fc00::", 7],
  ["fe80::", 10],
  ["ff00::", 8],
]

export function sha256(content) {
  return createHash("sha256").update(content).digest("hex")
}

export function contentLines(content) {
  return content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(
      (line) =>
        line !== "" &&
        !COMMENT_PREFIXES.some((prefix) => line.startsWith(prefix))
    )
}

export function normalizeDomain(
  raw,
  source = "domain list",
  { allowSingleLabel = false } = {}
) {
  const value = raw.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "")
  if (FORBIDDEN_DIRECTIVES.test(value) || /[\s/@:?\\]/.test(value)) {
    throw new Error(`${source}: forbidden domain value ${JSON.stringify(raw)}`)
  }
  const ascii = domainToASCII(value)
  if (
    !ascii ||
    ascii.length > 253 ||
    (!allowSingleLabel && !ascii.includes("."))
  ) {
    throw new Error(`${source}: invalid domain ${JSON.stringify(raw)}`)
  }
  const labels = ascii.split(".")
  if (
    labels.some(
      (label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)
    )
  ) {
    throw new Error(`${source}: invalid domain label in ${JSON.stringify(raw)}`)
  }
  return ascii
}

function ipv4ToBigInt(address) {
  return address
    .split(".")
    .reduce((result, octet) => (result << 8n) | BigInt(Number(octet)), 0n)
}

function ipv4FromBigInt(value) {
  return [24n, 16n, 8n, 0n]
    .map((shift) => Number((value >> shift) & 255n))
    .join(".")
}

function ipv6ToBigInt(address) {
  if (address.includes("."))
    throw new Error(`IPv4-mapped IPv6 is not supported: ${address}`)
  const halves = address.toLowerCase().split("::")
  if (halves.length > 2) throw new Error(`Invalid IPv6 address: ${address}`)
  const left = halves[0] ? halves[0].split(":") : []
  const right = halves[1] ? halves[1].split(":") : []
  const missing = 8 - left.length - right.length
  if (
    (halves.length === 1 && missing !== 0) ||
    (halves.length === 2 && missing < 1)
  ) {
    throw new Error(`Invalid IPv6 address: ${address}`)
  }
  const groups = [...left, ...Array(missing).fill("0"), ...right]
  return groups.reduce(
    (result, group) => (result << 16n) | BigInt(`0x${group || "0"}`),
    0n
  )
}

function addressToBigInt(address, family) {
  return family === 4 ? ipv4ToBigInt(address) : ipv6ToBigInt(address)
}

function networkBase(value, prefix, bits) {
  if (prefix === 0) return 0n
  const shift = BigInt(bits - prefix)
  return (value >> shift) << shift
}

function networksOverlap(left, right) {
  if (left.family !== right.family) return false
  const bits = left.family === 4 ? 32 : 128
  const commonPrefix = Math.min(left.prefix, right.prefix)
  return (
    networkBase(left.value, commonPrefix, bits) ===
    networkBase(right.value, commonPrefix, bits)
  )
}

function parseNetwork(raw, source) {
  const [addressRaw, prefixRaw, ...rest] = raw.trim().toLowerCase().split("/")
  if (rest.length > 0 || FORBIDDEN_DIRECTIVES.test(addressRaw)) {
    throw new Error(`${source}: invalid IP/CIDR ${JSON.stringify(raw)}`)
  }
  const family = isIP(addressRaw)
  if (family === 0)
    throw new Error(`${source}: invalid IP address ${JSON.stringify(raw)}`)
  const bits = family === 4 ? 32 : 128
  const prefix = prefixRaw === undefined ? bits : Number(prefixRaw)
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) {
    throw new Error(`${source}: invalid CIDR prefix ${JSON.stringify(raw)}`)
  }
  const value = addressToBigInt(addressRaw, family)
  const base = networkBase(value, prefix, bits)
  if (value !== base && prefix !== bits) {
    throw new Error(
      `${source}: CIDR must use its network address ${JSON.stringify(raw)}`
    )
  }
  return { address: addressRaw, family, prefix, value: base }
}

const FORBIDDEN_NETWORKS = [
  ...FORBIDDEN_IPV4.map(([address, prefix]) =>
    parseNetwork(`${address}/${prefix}`, "internal")
  ),
  ...FORBIDDEN_IPV6.map(([address, prefix]) =>
    parseNetwork(`${address}/${prefix}`, "internal")
  ),
]

export function normalizeIpCidr(
  raw,
  source = "IP/CIDR list",
  { allowReserved = false } = {}
) {
  const parsed = parseNetwork(raw, source)
  if (
    !allowReserved &&
    FORBIDDEN_NETWORKS.some((network) => networksOverlap(parsed, network))
  ) {
    throw new Error(
      `${source}: private or reserved network is forbidden in proxy rules: ${raw}`
    )
  }
  const address =
    parsed.family === 4 ? ipv4FromBigInt(parsed.value) : parsed.address
  return `${address}/${parsed.prefix}`
}

function sortedUnique(values) {
  return [...new Set(values)].sort((left, right) =>
    left < right ? -1 : left > right ? 1 : 0
  )
}

async function readRules(path, kind, options = {}) {
  const content = await readFile(path, "utf8")
  return contentLines(content).map((line) =>
    kind === "domain"
      ? normalizeDomain(line, path, options)
      : normalizeIpCidr(line, path, options)
  )
}

export async function loadCanonicalRules(root) {
  const lock = JSON.parse(
    await readFile(join(root, "upstream.lock.json"), "utf8")
  )
  if (!/^[0-9a-f]{40}$/.test(lock.source?.commit ?? ""))
    throw new Error("upstream.lock.json has an invalid commit")

  const proxyDomains = []
  const proxyIpCidrs = []
  const inputCounts = {}
  for (const input of lock.files) {
    const path = join(root, "vendor", "refilter", input.path)
    const content = await readFile(path)
    const digest = sha256(content)
    if (digest !== input.sha256)
      throw new Error(
        `${input.path}: expected SHA-256 ${input.sha256}, got ${digest}`
      )
    const values = contentLines(content.toString("utf8")).map((line) =>
      input.kind === "domain"
        ? normalizeDomain(line, input.path)
        : normalizeIpCidr(line, input.path)
    )
    if (values.length < input.minimumEntries) {
      throw new Error(
        `${input.path}: ${values.length} entries is below minimum ${input.minimumEntries}`
      )
    }
    inputCounts[input.path] = values.length
    if (input.kind === "domain") proxyDomains.push(...values)
    else proxyIpCidrs.push(...values)
  }

  proxyDomains.push(
    ...(await readRules(join(root, "rules/ctulhu/proxy-domains.txt"), "domain"))
  )
  proxyIpCidrs.push(
    ...(await readRules(join(root, "rules/ctulhu/proxy-ipcidr.txt"), "ipcidr"))
  )
  const directDomains = sortedUnique(
    await readRules(join(root, "rules/ctulhu/direct-domains.txt"), "domain", {
      allowSingleLabel: true,
    })
  )
  const directIpCidrs = sortedUnique(
    await readRules(join(root, "rules/ctulhu/direct-ipcidr.txt"), "ipcidr", {
      allowReserved: true,
    })
  )

  const directDomainSet = new Set(directDomains)
  const directIpSet = new Set(directIpCidrs)
  return {
    lock,
    inputCounts,
    directDomains,
    directIpCidrs,
    proxyDomains: sortedUnique(proxyDomains).filter(
      (value) => !directDomainSet.has(value)
    ),
    proxyIpCidrs: sortedUnique(proxyIpCidrs).filter(
      (value) => !directIpSet.has(value)
    ),
  }
}

function shadowrocketDomainList(values, description) {
  return `# ${description}\n${values.map((value) => `DOMAIN-SUFFIX,${value}`).join("\n")}\n`
}

function shadowrocketIpList(values, description) {
  return `# ${description}\n${values.map((value) => `${value.includes(":") ? "IP-CIDR6" : "IP-CIDR"},${value},no-resolve`).join("\n")}\n`
}

function mihomoDomainList(values) {
  // Mihomo's domain behavior treats bare values as exact hosts. The `+.`
  // wildcard preserves the repository contract that domain inputs are suffixes.
  return `${values.map((value) => `+.${value}`).join("\n")}\n`
}

function shadowrocketModule(publicBaseUrl) {
  const base = publicBaseUrl.replace(/\/$/, "")
  return `#!name=Ctulhu Smart Routing
#!desc=Selected domains and IP networks use the current proxy; all other traffic stays direct.

[Rule]
RULE-SET,${base}/shadowrocket/direct-domains.list,DIRECT
RULE-SET,${base}/shadowrocket/direct-ipcidr.list,DIRECT,no-resolve
RULE-SET,${base}/shadowrocket/domains.list,PROXY
RULE-SET,${base}/shadowrocket/ipcidr.list,PROXY,no-resolve
FINAL,DIRECT
`
}

function pacFile(directDomains, proxyDomains) {
  return `/**
 * Generated by ctulhu-vpn/routing-rules. Do not edit.
 * PAC is a legacy domain-only artifact; modern clients should use rule providers.
 */
var CTULHU_DIRECT_DOMAINS = ${JSON.stringify(directDomains)};
var CTULHU_PROXY_DOMAINS = ${JSON.stringify(proxyDomains)};
var CTULHU_PROXY = "SOCKS5 127.0.0.1:1086; DIRECT";
var CTULHU_DIRECT = "DIRECT";

function ctulhuDomainMatches(host, domain) {
  return host === domain || host.slice(-(domain.length + 1)) === "." + domain;
}

function ctulhuMatchesAny(host, domains) {
  for (var index = 0; index < domains.length; index += 1) {
    if (ctulhuDomainMatches(host, domains[index])) return true;
  }
  return false;
}

function FindProxyForURL(url, host) {
  var normalizedHost = String(host || "").toLowerCase().replace(/\\.$/, "");
  if (ctulhuMatchesAny(normalizedHost, CTULHU_DIRECT_DOMAINS)) return CTULHU_DIRECT;
  if (ctulhuMatchesAny(normalizedHost, CTULHU_PROXY_DOMAINS)) return CTULHU_PROXY;
  return CTULHU_DIRECT;
}
`
}

async function write(path, content) {
  await mkdir(dirname(path), { recursive: true })
  await writeFile(path, content)
}

export async function writeTextArtifacts(
  root,
  outputRoot,
  rules,
  publicBaseUrl
) {
  await rm(outputRoot, { recursive: true, force: true })
  await write(
    join(outputRoot, "shadowrocket/direct-domains.list"),
    shadowrocketDomainList(
      rules.directDomains,
      "Ctulhu direct domain exceptions"
    )
  )
  await write(
    join(outputRoot, "shadowrocket/direct-ipcidr.list"),
    shadowrocketIpList(rules.directIpCidrs, "Ctulhu direct IP/CIDR exceptions")
  )
  await write(
    join(outputRoot, "shadowrocket/domains.list"),
    shadowrocketDomainList(rules.proxyDomains, "Ctulhu smart proxy domains")
  )
  await write(
    join(outputRoot, "shadowrocket/ipcidr.list"),
    shadowrocketIpList(rules.proxyIpCidrs, "Ctulhu smart proxy IP/CIDR rules")
  )
  await write(
    join(outputRoot, "shadowrocket/ctulhu-smart.sgmodule"),
    shadowrocketModule(publicBaseUrl)
  )
  await write(
    join(outputRoot, "pac/proxy.pac"),
    pacFile(rules.directDomains, rules.proxyDomains)
  )

  const intermediate = join(root, "build/intermediate")
  await rm(intermediate, { recursive: true, force: true })
  await write(
    join(intermediate, "direct-domains.txt"),
    mihomoDomainList(rules.directDomains)
  )
  await write(
    join(intermediate, "direct-ipcidr.txt"),
    `${rules.directIpCidrs.join("\n")}\n`
  )
  await write(
    join(intermediate, "domains.txt"),
    mihomoDomainList(rules.proxyDomains)
  )
  await write(
    join(intermediate, "ipcidr.txt"),
    `${rules.proxyIpCidrs.join("\n")}\n`
  )
  return intermediate
}

async function artifactMetadata(outputRoot, path) {
  const content = await readFile(path)
  const info = await stat(path)
  return {
    path: relative(outputRoot, path).replaceAll("\\", "/"),
    bytes: info.size,
    sha256: sha256(content),
  }
}

export async function writeManifest(
  outputRoot,
  rules,
  artifactPaths,
  mihomoVersion,
  sourceCommit
) {
  const artifacts = []
  for (const path of artifactPaths.sort())
    artifacts.push(await artifactMetadata(outputRoot, path))
  const manifest = {
    schemaVersion: 1,
    rulesVersion: "v1",
    generatedAt: rules.lock.source.committedAt,
    ...(sourceCommit
      ? {
          source: {
            repository: "https://github.com/ctulhu-vpn/routing-rules",
            commit: sourceCommit,
          },
        }
      : {}),
    upstream: {
      repository: rules.lock.source.repository,
      commit: rules.lock.source.commit,
      committedAt: rules.lock.source.committedAt,
      license: rules.lock.source.license,
      inputs: rules.inputCounts,
    },
    toolchain: { mihomo: mihomoVersion },
    counts: {
      directDomains: rules.directDomains.length,
      directIpCidrs: rules.directIpCidrs.length,
      proxyDomains: rules.proxyDomains.length,
      proxyIpCidrs: rules.proxyIpCidrs.length,
    },
    artifacts,
  }
  await writeFile(
    join(outputRoot, "manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`
  )
  return manifest
}
