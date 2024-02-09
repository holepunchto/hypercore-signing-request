const HypercoreID = require('hypercore-id-encoding')
const Verifier = require('hypercore/lib/verifier')
const caps = require('hypercore/lib/caps')
const m = require('hypercore/lib/messages')
const c = require('compact-encoding')

const VERSION = 1

const Request = {
  preencode (state, req) {
    c.uint.preencode(state, req.version)
    c.uint.preencode(state, req.length)
    c.uint.preencode(state, req.fork)
    c.fixed32.preencode(state, req.treeHash)
    m.manifest.preencode(state, req.manifest)
  },
  encode (state, req) {
    c.uint.encode(state, req.version)
    c.uint.encode(state, req.length)
    c.uint.encode(state, req.fork)
    c.fixed32.encode(state, req.treeHash)
    m.manifest.encode(state, req.manifest)
  },
  decode (state) {
    const version = c.uint.decode(state)
    if (version !== VERSION) throw new Error('Unknown signing request version: ' + version)

    const length = c.uint.decode(state)
    const fork = c.uint.decode(state)
    const treeHash = c.fixed32.decode(state)
    const manifest = m.manifest.decode(state)

    const key = Verifier.manifestHash(manifest)
    const id = HypercoreID.normalize(key)

    return {
      version,
      id,
      key,
      length,
      fork,
      treeHash,
      manifest
    }
  }
}

module.exports = {
  async generate (core, { length = core.length, fork = core.fork } = {}) {
    if (!core.opened) await core.ready()

    if (core.core.compat) throw new Error('Cannot generate signing requests for compat cores')
    if (cork.fork !== fork) throw new Error('Core should have the same fork')

    return c.encode(Request, {
      version: VERSION,
      length,
      fork,
      treeHash: await core.treeHash(length),
      manifest: core.manifest
    })
  },
  decode (buffer) {
    const state = { start: 0, end: buffer.byteLength, buffer }
    const req = Request.decode(state)

    if (req.length === 0) throw new Error('Refusing to sign length = 0')
    if (state.start < state.end) throw new Error('Unparsed padding left in request, bailing')

    return req
  },
  signable (pub, req) {
    for (const s of req.manifest.signers) {
      if (s.publicKey.equals(pub)) {
        return caps.treeSignable(s.namespace, req.treeHash, req.length, req.fork)
      }
    }

    throw new Error('Public key is not a declared signer for this request')
  }
}
