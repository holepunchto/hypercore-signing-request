const test = require('brittle')
const Hypercore = require('hypercore')
const RAM = require('random-access-memory')
const { generate, decode } = require('./index')

test('Can generate and decode a signing request', async t => {
  const core = new Hypercore(RAM.reusable(), { compat: false })
  await core.append('Block 0')
  await core.append('Block 1')

  const toSign = await generate(core)
  const decoded = decode(toSign)

  t.is(decoded.version, 1, 'Current version is 1')
  t.alike(decoded.key, core.key, 'Currect key')
  t.is(decoded.length, 2, 'Correct length')
  t.is(decoded.fork, 0, 'correct fork')
  t.alike(decoded.treeHash, await core.treeHash(2), 'Correct treeHash')
  t.alike(decoded.manifest, core.manifest, 'Correct manifest')

  await core.close()
})