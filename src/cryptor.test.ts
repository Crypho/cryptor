import { expect } from "chai"
import * as cryptor from "./index"

describe('cryptor', () => {
  // Static Cryptor methods
  it('can generate an AES GCM key', async () => {
    const key = await cryptor.generateSymmetricKey()
    expect(key.algorithm.name).to.equal('AES-GCM')
    expect((key.algorithm as AesKeyAlgorithm).length).to.equal(256)
    expect(key.extractable).to.be.ok
  })

  it('can encrypt/decrypt utf8 strings using AES-GCM', async () => {
    const pt = 'Hello world'
    const key = await cryptor.generateSymmetricKey()
    const data = await cryptor.encryptSymmetric(pt, key)
    const dt = await cryptor.decryptSymmetric(
      data.ct,
      key,
      data.iv,
      data.additionalData
    )
    expect(new TextDecoder('utf-8').decode(dt)).to.equal(pt)
  })

  it('can generate an RSA-OAEP key', async () => {
    const keyPair = await cryptor.generateKeypair()
    const { publicKey, privateKey } = keyPair
    expect(publicKey.algorithm.name).to.equal('RSA-OAEP')
    expect((publicKey.algorithm as RsaKeyAlgorithm).modulusLength).to.equal(2048)
    expect(privateKey.algorithm.name).to.equal('RSA-OAEP')
    expect((privateKey.algorithm as RsaKeyAlgorithm).modulusLength).to.equal(2048)
  })

  it('can wrap/unwrap an AES-GCM key using RSA-OAEP', async () => {
    const pt = 'Hello world'
    const key = await cryptor.generateSymmetricKey()
    const data = await cryptor.encryptSymmetric(pt, key)
    const keyPair = await cryptor.generateKeypair()
    const wrapped = await cryptor.wrapKey(key, keyPair.publicKey)
    const unwrapped = await cryptor.unwrapKey(wrapped, keyPair.privateKey)
    const dt = await cryptor.decryptSymmetric(
      data.ct,
      unwrapped,
      data.iv,
      data.additionalData
    )
    expect(new TextDecoder('utf-8').decode(dt)).to.equal(pt)
  })

  it('can derive an AES 256-bit key from a passphrase using PBKDF2', async () => {
    const key = await cryptor.deriveKeyFromPassphrase('Password', 'salt')
    const exported = await window.crypto.subtle.exportKey('jwk', key)
    expect(exported.alg).to.equal('A256GCM')
    expect(exported.k).to.equal('_60NZIiD0VOqB-rwzptTLW3S2UBRfXlpItgSxqjLmew')
  })

  it('can derive an arbitrary number of bits from a passphrase using PBKDF2', async () => {
    const bits = await cryptor.deriveBitsFromPassphrase('password', 'salt', 64)
    expect(Array.from(bits)).to.equal([3, 148, 162, 237, 227, 50, 201, 161])
  })

  it('can generate authBits to be used for authentication', async () => {
    const authBits = await cryptor.generateAuthBits('password', 'salt')
    let c = new cryptor.Cryptor()
    await c.generate('password', 'salt')
    expect(c.authBits).to.equal(authBits)
  })

  // Instance methods
  it('can generate new instance of Cryptor from a passphrase', async () => {
    let c = new cryptor.Cryptor()
    await c.generate('password', 'salt')
    expect(c.keyPair).to.not.be.undefined
    expect(c.masterKey).to.not.be.undefined
    expect(c.authBits).to.not.be.undefined
  })

  it('can serialize/deserialize an instance of Cryptor', async () => {
    const c = new cryptor.Cryptor()
    await c.generate('password', 'salt')
    const json = await c.toJSON()
    let c2 = new cryptor.Cryptor()
    await c2.fromJSON(json, 'password', 'salt')

    expect(c.authBits).to.equal(c2.authBits)

    // We generate a random key and RSA encrypt it with c.
    // We then use that key to encrypt a test plain text.
    // We then decrypt the key with c2 and use it to retrieve the plaintext.

    const pt = 'Hello world'
    const key = await cryptor.generateSymmetricKey()
    const wrappedKey = await cryptor.wrapKey(key, c.keyPair.publicKey)
    const data = await cryptor.encryptSymmetric(pt, key)
    const unwrappedKey = await cryptor.unwrapKey(
      wrappedKey,
      c2.keyPair.privateKey
    )
    const dt = await cryptor.decryptSymmetric(
      data.ct,
      unwrappedKey,
      data.iv,
      data.additionalData
    )

    expect(new TextDecoder('utf-8').decode(dt)).to.equal(pt)
  })
})
