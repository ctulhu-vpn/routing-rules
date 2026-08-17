import assert from "node:assert/strict"
import { createHash } from "node:crypto"
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import test from "node:test"
import vm from "node:vm"
import {
  loadCanonicalRules,
  normalizeDomain,
  normalizeIpCidr,
  writeTextArtifacts,
} from "../scripts/lib/rules.mjs"

const repositoryRoot = resolve(new URL("../", import.meta.url).pathname)

function digest(content) {
  return createHash("sha256").update(content).digest("hex")
}

async function fixtureRepository() {
  const root = await mkdtemp(join(tmpdir(), "ctulhu-rules-test-"))
  await mkdir(join(root, "vendor/refilter"), { recursive: true })
  await mkdir(join(root, "rules/ctulhu"), { recursive: true })
  const inputs = {
    "domains_all.lst": "blocked.example\ndirect.example\n",
    "community.lst": "community.example\n",
    "community_ips.lst": "8.8.8.8/32\n",
    "discord_ips.lst": "1.1.1.0/24\n",
  }
  const files = []
  for (const [path, content] of Object.entries(inputs)) {
    await writeFile(join(root, "vendor/refilter", path), content)
    files.push({
      path,
      kind: path.includes("ips") ? "ipcidr" : "domain",
      minimumEntries: 1,
      sha256: digest(content),
    })
  }
  await writeFile(
    join(root, "upstream.lock.json"),
    JSON.stringify({
      schemaVersion: 1,
      source: {
        repository: "https://github.com/1andrevich/Re-filter-lists",
        commit: "0123456789abcdef0123456789abcdef01234567",
        committedAt: "2026-01-01T00:00:00Z",
        license: "MIT",
      },
      files,
    })
  )
  await writeFile(
    join(root, "rules/ctulhu/proxy-domains.txt"),
    "extra.example\n"
  )
  await writeFile(join(root, "rules/ctulhu/proxy-ipcidr.txt"), "9.9.9.9\n")
  await writeFile(
    join(root, "rules/ctulhu/direct-domains.txt"),
    "direct.example\n"
  )
  await writeFile(
    join(root, "rules/ctulhu/direct-ipcidr.txt"),
    "192.168.0.0/16\n"
  )
  return root
}

test("normalizes domains and rejects executable-looking values", () => {
  assert.equal(normalizeDomain("*.Example.COM."), "example.com")
  assert.throws(
    () => normalizeDomain("https://example.com"),
    /forbidden domain/
  )
  assert.throws(
    () => normalizeDomain("script.js/example.com"),
    /forbidden domain/
  )
})

test("normalizes IP networks and rejects private proxy ranges", () => {
  assert.equal(normalizeIpCidr("8.8.8.8"), "8.8.8.8/32")
  assert.equal(normalizeIpCidr("1.1.1.0/24"), "1.1.1.0/24")
  assert.throws(() => normalizeIpCidr("192.168.0.0/16"), /private or reserved/)
  assert.throws(() => normalizeIpCidr("8.8.8.1/24"), /network address/)
})

test("direct exceptions take precedence over exact upstream rules", async (context) => {
  const root = await fixtureRepository()
  context.after(() => rm(root, { recursive: true, force: true }))
  const rules = await loadCanonicalRules(root)
  assert.deepEqual(rules.directDomains, ["direct.example"])
  assert.equal(rules.proxyDomains.includes("direct.example"), false)
  assert.equal(rules.proxyDomains.includes("blocked.example"), true)
  assert.equal(rules.proxyIpCidrs.includes("9.9.9.9/32"), true)
})

test("writes deterministic Shadowrocket and PAC artifacts", async (context) => {
  const root = await fixtureRepository()
  context.after(() => rm(root, { recursive: true, force: true }))
  const output = join(root, "dist/v1")
  const rules = await loadCanonicalRules(root)
  await writeTextArtifacts(
    root,
    output,
    rules,
    "https://hub.example.invalid/routing-rules/v1"
  )

  const module = await readFile(
    join(output, "shadowrocket/ctulhu-smart.sgmodule"),
    "utf8"
  )
  assert.match(
    module,
    /RULE-SET,https:\/\/hub\.example\.invalid\/routing-rules\/v1\/shadowrocket\/domains\.list,PROXY/
  )
  assert.match(module, /FINAL,DIRECT\n$/)

  const pac = await readFile(join(output, "pac/proxy.pac"), "utf8")
  const contextObject = {}
  vm.runInNewContext(pac, contextObject)
  assert.equal(
    contextObject.FindProxyForURL("", "blocked.example"),
    "SOCKS5 127.0.0.1:1086; DIRECT"
  )
  assert.equal(
    contextObject.FindProxyForURL("", "sub.blocked.example"),
    "SOCKS5 127.0.0.1:1086; DIRECT"
  )
  assert.equal(
    contextObject.FindProxyForURL("", "notblocked.example"),
    "DIRECT"
  )
  assert.equal(contextObject.FindProxyForURL("", "direct.example"), "DIRECT")
})

test("pinned production inputs pass integrity and minimum-size checks", async () => {
  const rules = await loadCanonicalRules(repositoryRoot)
  assert.ok(rules.proxyDomains.length > 50000)
  assert.ok(rules.proxyIpCidrs.length > 1000)
  assert.ok(rules.proxyDomains.includes("docker.io"))
  assert.ok(rules.proxyDomains.includes("googlevideo.com"))
})

test("main publication waits for the Hub production rollout", async () => {
  const workflow = await readFile(
    join(repositoryRoot, ".github/workflows/build-and-publish.yml"),
    "utf8"
  )
  const publishJob = workflow.slice(
    workflow.indexOf("  publish:"),
    workflow.indexOf("  legacy-pac:")
  )
  assert.match(workflow, /main-\$\{GITHUB_SHA\}/)
  assert.match(workflow, /ROUTING_RULES_SOURCE_COMMIT/)
  assert.match(workflow, /CONFIGURED_PUBLIC_BASE_URL/)
  assert.match(workflow, /actions\/upload-artifact@v6/)
  assert.match(workflow, /actions\/download-artifact@v6/)
  assert.match(workflow, /--prerelease/)
  assert.match(workflow, /gzip -n/)
  assert.match(workflow, /HUB_WORKFLOW_TOKEN/)
  assert.match(workflow, /gh workflow run/)
  assert.match(workflow, /gh run watch/)
  assert.match(workflow, /createdAt/)
  assert.match(workflow, /--exit-status/)
  assert.match(publishJob, /actions\/checkout@v6/)
  assert.equal(workflow.includes("releases/latest"), false)
})
