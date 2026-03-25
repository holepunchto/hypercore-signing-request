const HypercoreID = require('hypercore-id-encoding')
const Hyperdrive = require('hyperdrive')
const Verifier = require('hypercore/lib/verifier')
const caps = require('hypercore/lib/caps')
const m = require('hypercore/lib/messages')
const c = require('compact-encoding')

const COMPAT_VERSION = 2
const MAX_SUPPORTED_VERSION = 3

const FLAG_DRIVE = 1
const REQUEST = 0
const RESPONSE = 1

const Request = {
  preencode (state, req) {
    c.uint.preencode(state, req.version)
    if (req.version > 2) {
      c.uint8.preencode(state, REQUEST)
    }

    c.uint.preencode(state, req.length)
    c.uint.preencode(state, req.fork)
    c.fixed32.preencode(state, req.treeHash)
    m.manifest.preencode(state, req.manifest)

    c.uint.preencode(state, 0) // flags

    if (req.content) {
      c.uint.preencode(state, req.content.length)
      c.fixed32.preencode(state, req.content.treeHash)
    }
  },
  encode (state, req) {
    c.uint.encode(state, req.version)
    if (req.version > 2) {
      c.uint8.encode(state, REQUEST)
    }

    c.uint.encode(state, req.length)
    c.uint.encode(state, req.fork)
    c.fixed32.encode(state, req.treeHash)
    m.manifest.encode(state, req.manifest)

    let flags = 0
    if (req.content) flags |= FLAG_DRIVE
    c.uint.encode(state, flags)

    if (req.content) {
      c.uint.encode(state, req.content.length)
      c.fixed32.encode(state, req.content.treeHash)
    }
  },
  decode (state) {
    const version = c.uint.decode(state)
    if (version > MAX_SUPPORTED_VERSION) {
      throw new Error('Unknown signing request version: ' + version)
    }

    const type = version < COMPAT_VERSION ? REQUEST : c.uint8.decode(state)
    if (type !== REQUEST) {
      throw new Error('Expected an encoded request')
    }

    const length = c.uint.decode(state)
    const fork = c.uint.decode(state)
    const treeHash = c.fixed32.decode(state)
    const manifest = m.manifest.decode(state)

    const key = Verifier.manifestHash(manifest)
    const id = HypercoreID.normalize(key)

    const flags = state.start !== state.end ? c.uint.decode(state) : 0

    let content = null

    const isHyperdrive = flags & FLAG_DRIVE
    if (isHyperdrive) {
      content = {
        length: c.uint.decode(state),
        treeHash: c.fixed32.decode(state)
      }
    }

    return {
      version,
      type,
      id,
      key,
      length,
      fork,
      treeHash,
      manifest,
      isHyperdrive,
      content
    }
  }
}

const Signatures = c.array(c.fixed64)

const Response = {
  preencode (state, res) {
    c.uint.preencode(state, res.version)
    if (res.version > 2) {
      c.uint8.preencode(state, RESPONSE)
    }

    c.fixed32.preencode(state, res.requestHash)
    c.fixed32.preencode(state, res.publicKey)
    Signatures.preencode(state, res.signatures)
  },
  encode (state, res) {
    c.uint.encode(state, res.version)
    if (res.version > 2) {
      c.uint8.encode(state, RESPONSE)
    }

    c.fixed32.encode(state, res.requestHash)
    c.fixed32.encode(state, res.publicKey)
    Signatures.encode(state, res.signatures)
  },
  decode (state, res) {
    const version = c.uint.decode(state)
    if (version > MAX_SUPPORTED_VERSION) {
      throw new Error('Response version is not supported, please upgrade')
    }

    const type = version > COMPAT_VERSION ? c.uint8.decode(state) : RESPONSE

    return {
      version,
      type,
      requestHash: c.fixed32.decode(state),
      publicKey: c.fixed32.decode(state),
      signatures: Signatures.decode(state)
    }
  }
}

module.exports = {
  generate,
  generateDrive,
  decode,
  encodeResponse,
  decodeResponse,
  signable
}

async function generate (core, { length = core.length, fork = core.fork, manifest = null } = {}) {
  if (!core.opened) await core.ready()

  if (core.blobs) return generateDrive(core, { length, fork, manifest })

  if (core.core.compat && !manifest) throw new Error('Cannot generate signing requests for compat cores')
  if (!manifest) manifest = core.manifest

  return c.encode(Request, {
    version: MAX_SUPPORTED_VERSION,
    length,
    fork,
    treeHash: await core.treeHash(length),
    manifest,
    content: null
  })
}

async function generateDrive (drive, { length = drive.core.length, fork = drive.core.fork, manifest = null }) {
  if (drive.core.core.compat && !manifest) throw new Error('Cannot generate signing requests for compat cores')

  if (!manifest) manifest = drive.core.manifest
  if (manifest < 1) throw new Error('Only v1 manifests are supported')

  const contentLength = await drive.getBlobsLength(length)
  const content = {
    length: contentLength,
    treeHash: await drive.blobs.core.treeHash(contentLength)
  }

  return c.encode(Request, {
    version: MAX_SUPPORTED_VERSION,
    length,
    fork,
    treeHash: await drive.core.treeHash(length),
    manifest,
    content
  })
}

function decode (buffer) {
  const state = { start: 0, end: buffer.byteLength, buffer }
  const req = Request.decode(state)

  if (req.length === 0) throw new Error('Refusing to sign length = 0')
  if (state.start < state.end) throw new Error('Unparsed padding left in request, bailing')

  return req
}

function encodeResponse (res) {
  return c.encode(Response, res)
}

function decodeResponse (buffer) {
  const state = { start: 0, end: buffer.byteLength, buffer }
  const res = Response.decode(state)

  if (state.start < state.end) throw new Error('Unparsed padding left in request, bailing')

  return res
}

function signable (pub, req) {
  const v = req.manifest.version

  for (let signer = 0; signer < req.manifest.signers.length; signer++) {
    const s = req.manifest.signers[signer]
    if (!s.publicKey.equals(pub)) continue

    if (req.isHyperdrive) return driveSignable(pub, req, signer)

    const signable = caps.treeSignable(v === 0 ? s.namespace : req.key, req.treeHash, req.length, req.fork)

    return [{ signer, signable }]
  }

  throw new Error('Public key is not a declared signer for this request')
}

function driveSignable (pub, req, signer) {
  const contentKey = Hyperdrive.getContentKey(req.manifest)
  if (!contentKey) {
    throw new Error('Drive is not compatible, needs v1 manifest')
  }

  const signable = caps.treeSignable(req.key, req.treeHash, req.length, req.fork)
  const content = caps.treeSignable(contentKey, req.content.treeHash, req.content.length, req.fork)

  return [
    { signer, signable },
    { signer, signable: content }
  ]
}
