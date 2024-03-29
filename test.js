const test = require('brittle')
const Hypercore = require('hypercore')
const Corestore = require('corestore')
const Hyperdrive = require('hyperdrive')
const RAM = require('random-access-memory')
const { generate, decode } = require('./index')

test('Can generate and decode a signing request', async t => {
  const core = new Hypercore(RAM.reusable(), { compat: false })
  await core.append('Block 0')
  await core.append('Block 1')

  const toSign = await generate(core)
  const decoded = decode(toSign)

  t.is(decoded.version, 2, 'Current version is corrects')
  t.alike(decoded.key, core.key, 'Currect key')
  t.is(decoded.length, 2, 'Correct length')
  t.is(decoded.fork, 0, 'correct fork')
  t.alike(decoded.treeHash, await core.treeHash(2), 'Correct treeHash')
  t.alike(decoded.manifest, core.manifest, 'Correct manifest')
  t.absent(decoded.isHyperdrive)
  t.is(decoded.content, null)

  await core.close()
})

test('Can generate and decode a drive request', async t => {
  const store = new Corestore(RAM, { manifestVersion: 1, compat: false })
  await store.ready()

  const drive = new Hyperdrive(store)
  await drive.ready()

  await drive.put('./hello.txt', Buffer.from('hello'))
  await drive.put('./world.txt', Buffer.from('world'))

  const toSign = await generate(drive)
  const decoded = decode(toSign)

  t.is(decoded.version, 2, 'Current version is correct')
  t.alike(decoded.key, drive.core.key, 'Currect key')
  t.is(decoded.length, 3, 'Correct length')
  t.is(decoded.fork, 0, 'correct fork')
  t.alike(decoded.treeHash, await drive.core.treeHash(3), 'Correct treeHash')
  t.alike(decoded.manifest, drive.core.manifest, 'Correct manifest')

  t.ok(decoded.isHyperdrive)
  t.ok(decoded.content)
  t.is(decoded.content.length, drive.blobs.core.length)
  t.alike(decoded.content.treeHash, await drive.blobs.core.treeHash())

  await drive.close()
})
