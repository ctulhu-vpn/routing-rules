import { createHash } from "node:crypto"
import { gunzipSync } from "node:zlib"
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises"
import { join } from "node:path"
import process from "node:process"
import { fileURLToPath } from "node:url"

const root = fileURLToPath(new URL("../", import.meta.url))
const lock = JSON.parse(
  await readFile(join(root, "toolchain.lock.json"), "utf8")
)
const targetName = `${process.platform}-${process.arch}`
const target = lock.targets[targetName]
if (!target) throw new Error(`No pinned Mihomo binary for ${targetName}`)

const toolsDirectory = join(root, "tools")
const binaryPath = join(toolsDirectory, "mihomo")
const markerPath = join(toolsDirectory, "mihomo.json")

async function existingBinaryMatches() {
  try {
    const marker = JSON.parse(await readFile(markerPath, "utf8"))
    const binary = await readFile(binaryPath)
    return (
      marker.version === lock.mihomoVersion &&
      marker.target === targetName &&
      marker.binarySha256 === createHash("sha256").update(binary).digest("hex")
    )
  } catch {
    return false
  }
}

if (await existingBinaryMatches()) {
  console.log(
    `Mihomo ${lock.mihomoVersion} is already installed at ${binaryPath}`
  )
  process.exit(0)
}

const response = await fetch(target.url, {
  headers: process.env.GITHUB_TOKEN
    ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` }
    : {},
})
if (!response.ok)
  throw new Error(`Failed to download Mihomo: HTTP ${response.status}`)
const archive = Buffer.from(await response.arrayBuffer())
const archiveSha256 = createHash("sha256").update(archive).digest("hex")
if (archiveSha256 !== target.sha256) {
  throw new Error(
    `Mihomo archive checksum mismatch: expected ${target.sha256}, got ${archiveSha256}`
  )
}

const binary = gunzipSync(archive)
const binarySha256 = createHash("sha256").update(binary).digest("hex")
await mkdir(toolsDirectory, { recursive: true })
await writeFile(binaryPath, binary, { mode: 0o755 })
await chmod(binaryPath, 0o755)
await writeFile(
  markerPath,
  `${JSON.stringify(
    {
      version: lock.mihomoVersion,
      target: targetName,
      archiveSha256,
      binarySha256,
    },
    null,
    2
  )}\n`
)
console.log(`Installed Mihomo ${lock.mihomoVersion} at ${binaryPath}`)
