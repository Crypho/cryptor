# Cryptor API

## Requirements and usage

Cryptor depends on the availability of `SubtleCrypto` API on browsers. (browser compatibility [here](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto)).

Additionally we rely on the `Promise` API (compatibility [here](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise)).

Finally we use the `async/await` operators (compatibility [here](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/await)).

## Instantiation and serialization/deserialization

A new instance of can be generated from a passphrase as such:

```
const c = new cryptor.Cryptor()
await c.generate('password', 'salt')
```

The instance can then be serialized

```
c.toJSON()
.then((json) => {
  // Upload json to the server and save
})
```

Later, the instance can be retrieved using the same json data, passphrase and salt:

```
let c2 = new cryptor.Cryptor()
await c2.fromJSON(json, 'password', 'salt')
```

## Encryptiion/decryption

Cryptor uses AES-GCM for encryption/decryption.

```
const pt = 'Hello world'
const key = await cryptor.generateSymmetricKey()
const data = await cryptor.encryptSymmetric(pt, key)
```

`data` contains the cipher text, iv and AES additional data. the plain text can be retrieved using the same key as such:

```
const dt = await cryptor.decryptSymmetric(data.ct, key, data.iv, data.additionalData)
const decrypted = new TextDecoder('utf-8').decode(dt) // Decrypted is now 'Hello world'
```

## Key wrapping/unwrapping

A key can be "wrapped" using an RSA-OAEP public key and later "unwrapped" using the keypair's private key. This allows for safe communication of keys.

For example:

```
const key = await cryptor.generateSymmetricKey()
const keyPair = await cryptor.generateKeypair()
const wrapped = await cryptor.wrapKey(key, keyPair.publicKey)
const unwrapped = await cryptor.unwrapKey(wrapped, keyPair.privateKey)
```

At the end of this process the `unwrapped` key is equivalent to `key`.

## Key and data derivation from passphrases

Cryptor can derive an 256-bit AES from a passphrase by means of the PBKDF2 key derivation function.

```
const key = await cryptor.deriveKeyFromPassphrase('Password', 'salt')
```

It is also possible to derive an arbitrary number of bits. This can be useful for authentication for example.

```
const bits = await cryptor.deriveBitsFromPassphrase('password', 'salt', 64)
Array.fromBits(bits) // This is now an array of bytes (unsigned int 8) of length 8
```

# Example

Alice wants to register with the chat app ChatX and converse with Bob. ChatX uses Cryptor to secure its users' communications.

## Registration

Alice registers with ChatX by generating a Cryptor instance, serializing it and passing it to the server.

```
const c = new cryptor.Cryptor()
await c.generate('hunter2', 'chatx:alice@foo.com')
const json = await c.toJSON()
```

the `json` looks similar to and can be passsed to the server together with the salt:

```
{
  authBits: Uint8Array []
  privateKeyEncrypted: {
    ct: "5OVV6QiJPgOJcXmxmzdKlTi11+D8E9Q29/KQoZxV9sMpVrzxk+…b8zbLPEft0awth4nY1zBwhhCM/YH4xnswVmXEkqaAWtLq7g==",
    iv: "w4AhlavThQP++YHG",
    additionalData: "yv5YgLh4mnqrcFug"
  }
  publicKey: {
    alg: "RSA-OAEP-256",
    e: "AQAB",
    ext: true,
    key_ops: Array(1),
    kty: "RSA",
    …
  }
}
```

## Authentication

Later, Alice can log in to ChatX by following these steps:

First she authenicates to ChatX by proving she knows her passphrase:

```
const authBits = cryptor.generateAuthBits('hunter2', 'chatx:alice@foo.com')
```

She shares `authBits` with ChatX who confirms it's identical to the ones stored on the server. Hence, ChatX returns the credentials json to Alice who uses it to recover her keypair.

```
let c = new cryptor.Cryptor()
await c.fromJSON(json, 'hunter2', 'chatx:alice@foo.com')
```

## Sharing a key and encrypting messages

When Alice and Bob need to chat securely, one of them creates a key and then shares it. For example if Alice starts the conversation she will fetch Bob's public key `bobPublicKey` from the server and

```
const key = await cryptor.generateSymmetricKey()
const wrappedKeyForBob = await cryptor.wrapKey(key, bobPublicKey)
```

If ChatX supposrts resuming conversations later, it will be useful for Alice to keep a copy of the key encrypted to her own public key. So assuming `cAlice` is her instance of Cryptor:

```
const wrappedKeyForAlice = await cryptor.wrapKey(key, cAlice.keyPair.publicKey)
```

She can then share both wrapped keys to the server.

Now she is ready to send a message. She can encrypt it using the key she has generated and send it to the server for storage.

```
const ct = await cryptor.encryptSymmetric('Hello world', key)
```

## Using a shared key and decrypting messages

Bob who has authenticated is informed he has a new message from Alice. He retrieves his copy of the wrapped key `wrappedKeyForBob` as well as the cipher text `ct`.

Assuming `cBob` is his Cryptor instance, first he unwraps the key, then he decrypts the message:

```
const key = cryptor.unwrapKey(
  wrappedKey,
  cBob.keyPair.privateKey
)
const pt = await cryptor.decryptSymmetric(
  ct.ct,
  key,
  ct.iv,
  ct.additionalData
)
```

He can of course reply using the same key and continue the conversation.
