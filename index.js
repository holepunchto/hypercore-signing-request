const HypercoreID = require('hypercore-id-encoding')
const Verifier = require('hypercore/lib/verifier')
const caps = require('hypercore/lib/caps')
const m = require('hypercore/lib/messages')
const c = require('compact-encoding')

module.exports = {
  generate (core) {
    if (core.core.compat) throw new Error('Cannot generate signing requests for compat cores')

    const version = c.encode(c.uint, 0)
    const manifest = c.encode(c.buffer, c.encode(m.manifest, core.manifest))
    const treeHash = c.encode(c.fixed32, core.core.tree.hash())
    const length = c.encode(c.uint, core.length)
    const fork = c.encode(c.uint, core.fork)

    return Buffer.concat([version, manifest, treeHash, length, fork])
  },
  decode (req) {
    const state = { start: 0, end: req.byteLength, buffer: req }
    const version = c.uint.decode(state)

    if (version !== 0) throw new Error('Unknown signing request version: ' + version)

    const manifest = c.decode(m.manifest, c.buffer.decode(state))
    const treeHash = c.fixed32.decode(state)
    const length = c.uint.decode(state)
    const fork = c.uint.decode(state)

    if (length === 0) throw new Error('Refusing to sign length = 0')
    if (state.start < state.end) throw new Error('Unparsed padding left in request, bailing')

    const key = Verifier.manifestHash(manifest)
    const id = HypercoreID.normalize(key)

    return {
      version,
      id,
      key,
      manifest,
      treeHash,
      length,
      fork
    }
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
