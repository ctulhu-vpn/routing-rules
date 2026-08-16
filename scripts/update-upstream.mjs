import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { basename, join, resolve } from "node:path"
import process from "node:process"
import { fileURLToPath } from "node:url"
import {
  contentLines,
  normalizeDomain,
  normalizeIpCidr,
  sha256,
} from "./lib/rules.mjs"

const root = resolve(fileURLToPath(new URL("../", import.meta.url)))
const lockPath = join(root, "upstream.lock.json")
const lock = JSON.parse(await readFile(lockPath, "utf8"))
const requestedCommit = process.argv
  .find((argument) => argument.startsWith("--commit="))
  ?.split("=")[1]
const headers = process.env.GITHUB_TOKEN
  ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` }
  : {}

async function fetchBuffer(url) {
  const response = await fetch(url, { headers })
  if (!response.ok) throw new Error(`GET ${url}: HTTP ${response.status}`)
  return Buffer.from(await response.arrayBuffer())
}

const commitResponse = await fetch(
  `https://api.github.com/repos/1andrevich/Re-filter-lists/commits/${requestedCommit ?? "main"}`,
  { headers: { ...headers, Accept: "application/vnd.github+json" } }
)
if (!commitResponse.ok)
  throw new Error(
    `Unable to resolve Re:filter commit: HTTP ${commitResponse.status}`
  )
const commitData = await commitResponse.json()
const commit = commitData.sha
if (!/^[0-9a-f]{40}$/.test(commit))
  throw new Error(`GitHub returned invalid commit ${commit}`)

const temporaryDirectory = await mkdtemp(
  join(tmpdir(), "ctulhu-routing-rules-")
)
const downloaded = []
try {
  for (const input of lock.files) {
    const url = `https://raw.githubusercontent.com/1andrevich/Re-filter-lists/${commit}/${input.path}`
    const content = await fetchBuffer(url)
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
    const temporaryPath = join(temporaryDirectory, basename(input.path))
    await writeFile(temporaryPath, content)
    downloaded.push({ input, temporaryPath, sha256: sha256(content) })
  }

  for (const item of downloaded) {
    await writeFile(
      join(root, "vendor/refilter", item.input.path),
      await readFile(item.temporaryPath)
    )
    item.input.sha256 = item.sha256
  }
  lock.source.commit = commit
  lock.source.committedAt = commitData.commit.committer.date
  await writeFile(lockPath, `${JSON.stringify(lock, null, 2)}\n`)
  console.log(`Pinned Re:filter ${commit}`)
} finally {
  await rm(temporaryDirectory, { recursive: true, force: true })
}
