# hypercore-signing-request

Generate shareable signing requests for Hypercore

```
npm install hypercore-signing-request
```

Useful for manual multisig

## Usage

``` js
const { generate, decode, signable } = require('hypercore-signing-request')
```

## API

#### `requestBuffer = await generate(coreOrDrive, { length = core.length })`

Generate a signing request, returned as a buffer so it can be shared.
Only works for non-compat cores (ie manifest backed).

Alternatvely a Hyperdrive can be passed and a joint request for signing both metadata and blob cores will be generated.
Only works for v1 manifest backed Hyperdrives.


#### `req = decode(requestBuffer)`

Decode the signing request. Looks like this:

``` js
{
  version, // request version
  id, // hypercore id
  key, // the key as well
  manifest, // core manifest
  treeHash, // the tree hash
  length, // the core length
  fork // the core fork id
}
```

#### `buffer = signable(publicKey, req)`

Get the buffer to sign. Pass your public key and it validates that you can sign it.

## License

Apache-2.0
