import { execFileSync } from "node:child_process"
import { access, copyFile, mkdir, readFile, rm } from "node:fs/promises"
import { join, resolve } from "node:path"
import process from "node:process"
import { fileURLToPath } from "node:url"
import {
  loadCanonicalRules,
  writeManifest,
  writeTextArtifacts,
} from "./lib/rules.mjs"

const root = resolve(fileURLToPath(new URL("../", import.meta.url)))
const outputRoot = join(root, "dist/v1")
const publicBaseUrl =
  process.env.ROUTING_RULES_PUBLIC_BASE_URL ??
  "https://hub.example.invalid/routing-rules/v1"
if (!/^https:\/\/[^/]+\/routing-rules\/v1\/?$/.test(publicBaseUrl)) {
  throw new Error(
    "ROUTING_RULES_PUBLIC_BASE_URL must be an HTTPS /routing-rules/v1 URL"
  )
}
const sourceCommit = process.env.ROUTING_RULES_SOURCE_COMMIT
if (sourceCommit && !/^[0-9a-f]{40}$/.test(sourceCommit)) {
  throw new Error("ROUTING_RULES_SOURCE_COMMIT must be a 40-hex commit SHA")
}

const toolchain = JSON.parse(
  await readFile(join(root, "toolchain.lock.json"), "utf8")
)
const mihomo = resolve(process.env.MIHOMO_BIN ?? join(root, "tools/mihomo"))
await access(mihomo).catch(() => {
  throw new Error(
    "Pinned Mihomo binary is missing; run npm run setup:mihomo first"
  )
})

const rules = await loadCanonicalRules(root)
const intermediate = await writeTextArtifacts(
  root,
  outputRoot,
  rules,
  publicBaseUrl
)
const conversions = [
  ["domain", "direct-domains"],
  ["ipcidr", "direct-ipcidr"],
  ["domain", "domains"],
  ["ipcidr", "ipcidr"],
]
const artifactPaths = [
  join(outputRoot, "shadowrocket/ctulhu-smart.sgmodule"),
  join(outputRoot, "shadowrocket/direct-domains.list"),
  join(outputRoot, "shadowrocket/direct-ipcidr.list"),
  join(outputRoot, "shadowrocket/domains.list"),
  join(outputRoot, "shadowrocket/ipcidr.list"),
  join(outputRoot, "pac/proxy.pac"),
]

await mkdir(join(outputRoot, "licenses"), { recursive: true })
await mkdir(join(outputRoot, "mihomo"), { recursive: true })
for (const [source, name] of [
  [join(root, "LICENSE"), "ctulhu-vpn-MIT.txt"],
  [join(root, "vendor/refilter/LICENSE"), "re-filter-MIT.txt"],
]) {
  const destination = join(outputRoot, "licenses", name)
  await copyFile(source, destination)
  artifactPaths.push(destination)
}

for (const [behavior, name] of conversions) {
  const input = join(intermediate, `${name}.txt`)
  const output = join(outputRoot, `mihomo/${name}.mrs`)
  execFileSync(mihomo, ["convert-ruleset", behavior, "text", input, output], {
    stdio: "inherit",
  })
  artifactPaths.push(output)
}

await rm(intermediate, { recursive: true, force: true })
const manifest = await writeManifest(
  outputRoot,
  rules,
  artifactPaths,
  toolchain.mihomoVersion,
  sourceCommit
)
console.log(
  `Built ${manifest.counts.proxyDomains} proxy domains and ${manifest.counts.proxyIpCidrs} proxy networks`
)
