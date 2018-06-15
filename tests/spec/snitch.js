describe('Player', () => {
  let snitch

  beforeEach(() => {
    snitch = window.snitch
  })

  it('should define a namespace', () => {
    expect(window.snitch).toBeDefined()
  })

  it('can generate a symmetric key', done => {
    snitch.generateSymmetricKey().then(key => {
      expect(key.algorithm.name).toEqual('AES-GCM')
      expect(key.algorithm.length).toEqual(256)
      expect(key.extractable).toBeTruthy()
      done()
    })
  })

  it('can encrypt/decrypt utf8 strings using symmetric crypto', async done => {
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
})
