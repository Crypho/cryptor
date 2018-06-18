describe('Player', () => {
  let snitch

  beforeEach(() => {
    snitch = window.snitch
  })

  it('should define a namespace', () => {
    expect(window.snitch).toBeDefined()
  })

  it('can generate an AES GCM key', done => {
    snitch.generateSymmetricKey().then(key => {
      expect(key.algorithm.name).toEqual('AES-GCM')
      expect(key.algorithm.length).toEqual(256)
      expect(key.extractable).toBeTruthy()
      done()
    })
  })

  it('can encrypt/decrypt utf8 strings using AES-GCM', async done => {
    const pt = 'Hello world'
    const key = await snitch.generateSymmetricKey()
    const data = await snitch.encryptSymmetric(pt, key)
    const dt = await snitch.decryptSymmetric(
      data.ct,
      key,
      data.iv,
      data.additionalData
    )
    expect(new TextDecoder('utf-8').decode(dt)).toEqual(pt)
    done()
  })

  it('can generate an RSA-OAEP key', done => {
    snitch.generateKeypair().then(keyPair => {
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
    const key = await snitch.generateSymmetricKey()
    const data = await snitch.encryptSymmetric(pt, key)
    const keyPair = await snitch.generateKeypair()
    const wrapped = await snitch.wrapKey(key, keyPair.publicKey)
    const unwrapped = await snitch.unwrapKey(wrapped, keyPair.privateKey)
    const dt = await snitch.decryptSymmetric(
      data.ct,
      unwrapped,
      data.iv,
      data.additionalData
    )
    expect(new TextDecoder('utf-8').decode(dt)).toEqual(pt)
    done()
  })
})
