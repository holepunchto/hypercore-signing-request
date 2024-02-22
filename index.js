const HypercoreID = require('hypercore-id-encoding')
const Verifier = require('hypercore/lib/verifier')
const caps = require('hypercore/lib/caps')
const m = require('hypercore/lib/messages')
const c = require('compact-encoding')
const crypto = require('hypercore-crypto')

const [BLOBS] = crypto.namespace('hyperdrive', 1)

const VERSION = 2
const FLAG_DRIVE = 1

const Request = {
  preencode (state, req) {
    c.uint.preencode(state, req.version)
    c.uint.preencode(state, req.length)
    c.uint.preencode(state, req.fork)
    c.fixed32.preencode(state, req.treeHash)
    m.manifest.preencode(state, req.manifest)

    c.uint.preencode(state, 0) // flags

    if (req.blobs) {
      c.uint.preencode(state, req.blobs.length)
      c.fixed32.preencode(state, req.blobs.treeHash)
    }
  },
  encode (state, req) {
    c.uint.encode(state, req.version)
    c.uint.encode(state, req.length)
    c.uint.encode(state, req.fork)
    c.fixed32.encode(state, req.treeHash)
    m.manifest.encode(state, req.manifest)

    let flags = 0
    if (req.blobs) flags |= FLAG_DRIVE
    c.uint.encode(state, flags)

    if (req.blobs) {
      c.uint.encode(state, req.blobs.length)
      c.fixed32.encode(state, req.blobs.treeHash)
    }
  },
  decode (state) {
    const version = c.uint.decode(state)
    if (version > VERSION) throw new Error('Unknown signing request version: ' + version)

    const length = c.uint.decode(state)
    const fork = c.uint.decode(state)
    const treeHash = c.fixed32.decode(state)
    const manifest = m.manifest.decode(state)

    const key = Verifier.manifestHash(manifest)
    const id = HypercoreID.normalize(key)

    const flags = state.start !== state.end ? c.uint.decode(state) : 0

    let blobs = null

    if (flags & FLAG_DRIVE) {
      blobs = {
        length: c.uint.decode(state),
        treeHash: c.fixed32.decode(state)
      }
    }

    return {
      version,
      id,
      key,
      length,
      fork,
      treeHash,
      manifest,
      blobs
    }
  }
}

module.exports = {
  generate,
  generateDrive,
  decode,
  signable
}

async function generate (core, { length = core.length, fork = core.fork, manifest = null } = {}) {
  if (!core.opened) await core.ready()

  if (core.blobs) return generateDrive(core, { length, fork, manifest })

  if (core.core.compat && !manifest) throw new Error('Cannot generate signing requests for compat cores')
  if (core.fork !== fork) throw new Error('Core should have the same fork')
  if (!manifest) manifest = core.manifest

  return c.encode(Request, {
    version: VERSION,
    length,
    fork,
    treeHash: await core.treeHash(length),
    manifest,
    blobs: null
  })
}

async function generateDrive (drive, { length = drive.core.length, fork = drive.core.fork, manifest = null }) {
  if (drive.core.core.compat && !manifest) throw new Error('Cannot generate signing requests for compat cores')

  if (!manifest) manifest = drive.core.manifest
  if (manifest < 1) throw new Error('Only v1 manifests are supported')

  const last = await drive.db.getBySeq(length - 1)
  const { blockOffset, blockLength } = last.value.blob

  const blobsLength = blockOffset + blockLength
  const blobs = {
    length: blobsLength,
    treeHash: await drive.blobs.core.treeHash(blobsLength)
  }

  return c.encode(Request, {
    version: VERSION,
    length,
    fork,
    treeHash: await drive.core.treeHash(length),
    manifest,
    blobs
  })
}

function decode (buffer) {
  const state = { start: 0, end: buffer.byteLength, buffer }
  const req = Request.decode(state)

  if (req.length === 0) throw new Error('Refusing to sign length = 0')
  if (state.start < state.end) throw new Error('Unparsed padding left in request, bailing')

  return req
}

function signable (pub, req) {
  const v = req.manifest.version
  for (const s of req.manifest.signers) {
    if (s.publicKey.equals(pub)) {
      const signable = caps.treeSignable(v === 0 ? s.namespace : req.key, req.treeHash, req.length, req.fork)
      if (req.blobs === null) return [signable]

      const m = req.manifest
      if (m.version < 1) {
        throw new Error('Drive must use v1 manifests')
      }

      const namespace = crypto.hash([BLOBS, req.key, s.namespace])
      const blobs = caps.treeSignable(namespace, req.treeHash, req.length, req.fork)

      return [
        signable,
        blobs
      ]
    }
  }

  throw new Error('Public key is not a declared signer for this request')
}
