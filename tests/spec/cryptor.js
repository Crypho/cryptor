describe('cryptor', () => {
  let cryptor

  beforeEach(() => {
    cryptor = window.cryptor
  })

  it('can generate an AES GCM key', done => {
    cryptor.generateSymmetricKey().then(key => {
      expect(key.algorithm.name).toEqual('AES-GCM')
      expect(key.algorithm.length).toEqual(256)
      expect(key.extractable).toBeTruthy()
      done()
    })
  })

  it('can encrypt/decrypt utf8 strings using AES-GCM', async done => {
    const pt = 'Hello world'
    const key = await cryptor.generateSymmetricKey()
    const data = await cryptor.encryptSymmetric(pt, key)
    const dt = await cryptor.decryptSymmetric(
      data.ct,
      key,
      data.iv,
      data.additionalData
    )
    expect(new TextDecoder('utf-8').decode(dt)).toEqual(pt)
    done()
  })

  it('can generate an RSA-OAEP key', done => {
    cryptor.generateKeypair().then(keyPair => {
      const { publicKey, privateKey } = keyPair
      expect(publicKey.algorithm.name).toEqual('RSA-OAEP')
      expect(publicKey.algorithm.modulusLength).toEqual(2048)
      expect(privateKey.algorithm.name).toEqual('RSA-OAEP')
      expect(privateKey.algorithm.modulusLength).toEqual(2048)
      done()
    })
  })

  it('can wrap/unwrap an AES-GCM key using RSA-OAEP', async done => {
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
    expect(new TextDecoder('utf-8').decode(dt)).toEqual(pt)
    done()
  })

  it('can generate an AES 256-bit key from a passphrase using PBKDF2', async done => {
    const key = await cryptor.deriveKeyFromPassphrase('Password', 'salt')
    const exported = await window.crypto.subtle.exportKey('jwk', key)
    expect(exported.alg).toEqual('A256GCM')
    expect(exported.k).toEqual('uSaTpRqjQPQx4YZqiIHcwruFA2De-5U6Q22xXSvqLZM')
    done()
  })
})
