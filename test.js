const test = require('brittle')
const Hypercore = require('hypercore')
const Corestore = require('corestore')
const Hyperdrive = require('hyperdrive')
const { generate, decode, encodeResponse, decodeResponse, isRequest, isResponse } = require('./index')

test('Can generate and decode a signing request', async t => {
  const core = new Hypercore(await t.tmp(), { compat: false })
  await core.append('Block 0')
  await core.append('Block 1')

  const toSign = await generate(core)
  const decoded = decode(toSign)

  t.is(decoded.version, 3, 'Current version is corrects')
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
  const store = new Corestore(await t.tmp(), { manifestVersion: 1, compat: false })
  await store.ready()

  const drive = new Hyperdrive(store)
  await drive.ready()

  await drive.put('./hello.txt', Buffer.from('hello'))
  await drive.put('./world.txt', Buffer.from('world'))

  const toSign = await generate(drive)
  const decoded = decode(toSign)

  t.is(decoded.version, 3, 'Current version is correct')
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

test('Request and response encodings', async t => {
  const store = new Corestore(await t.tmp(), { manifestVersion: 1, compat: false })
  await store.ready()

  const drive = new Hyperdrive(store)
  await drive.ready()

  await drive.put('./hello.txt', Buffer.from('hello'))
  await drive.put('./world.txt', Buffer.from('world'))

  const request = await generate(drive)

  const response = {
    version: 3,
    publicKey: Buffer.alloc(32, 1),
    requestHash: Buffer.alloc(32, 2),
    signatures: [
      Buffer.alloc(64, 1),
      Buffer.alloc(64, 2)
    ]
  }

  const encodedV3 = encodeResponse(response)

  response.version = 2
  const encodedV2 = encodeResponse(response)

  t.exception(() => decodeResponse(request))
  t.exception(() => decode(encodedV3))

  const decodedRequest = decode(request)
  const decodedResponseV2 = decodeResponse(encodedV2)
  const decodedResponseV3 = decodeResponse(encodedV3)

  t.is(decodedRequest.version, 3, 'Current version is correct')
  t.alike(decodedRequest.key, drive.core.key, 'Currect key')
  t.is(decodedRequest.length, 3, 'Correct length')
  t.is(decodedRequest.fork, 0, 'correct fork')
  t.alike(decodedRequest.treeHash, await drive.core.treeHash(3), 'Correct treeHash')
  t.alike(decodedRequest.manifest, drive.core.manifest, 'Correct manifest')

  t.ok(decodedRequest.isHyperdrive)
  t.ok(decodedRequest.content)
  t.is(decodedRequest.content.length, drive.blobs.core.length)
  t.alike(decodedRequest.content.treeHash, await drive.blobs.core.treeHash())

  t.is(decodedResponseV2.version, 2, 'Response v2 version is correct')
  t.is(decodedResponseV3.version, 3, 'Response v3 version is correct')

  t.ok(isRequest(request))
  t.absent(isResponse(request))

  t.absent(isRequest(encodedV3))
  t.ok(isResponse(encodedV3))

  await drive.close()
})
