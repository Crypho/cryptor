;((root, factory) => {
  if (typeof define === 'function' && define.amd) {
    // AMD
    define([], factory)
  } else if (typeof exports === 'object') {
    // Node, CommonJS-like
    module.exports = factory()
  } else {
    // Browser globals (root is window)
    root.cryptor = factory()
  }
})(this, () => {
  const crypto = window.crypto.subtle

  const exports = {
    generateSymmetricKey() {
      return crypto.generateKey(
        {
          name: 'AES-GCM',
          length: 256,
        },
        true, // make key extractable
        ['encrypt', 'decrypt']
      )
    },

    encryptSymmetric(pt, key) {
      if (typeof pt === 'string') {
        // Convert to ArrayBuffer
        pt = new TextEncoder('utf-8').encode(pt)
      }
      const iv = window.crypto.getRandomValues(new Uint8Array(12))
      const additionalData = window.crypto.getRandomValues(new Uint8Array(12))
      return crypto
        .encrypt(
          {
            name: 'AES-GCM',
            iv,
            additionalData,
            tagLength: 128,
          },
          key,
          pt
        )
        .then(ct => {
          return {
            ct: new Uint8Array(ct),
            iv,
            additionalData,
          }
        })
    },

    decryptSymmetric(ct, key, iv, additionalData) {
      return crypto.decrypt(
        {
          name: 'AES-GCM',
          iv,
          additionalData,
          tagLength: 128,
        },
        key,
        ct
      )
    },

    generateKeypair() {
      return crypto.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: 2048,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          hash: { name: 'SHA-256' },
        },
        true, // make key extrctable
        ['wrapKey', 'unwrapKey']
      )
    },

    wrapKey(key, publicKey) {
      return crypto.wrapKey('raw', key, publicKey, {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: 'SHA-256' },
      })
    },

    unwrapKey(wrapped, privateKey) {
      return crypto.unwrapKey(
        'raw',
        wrapped,
        privateKey,
        {
          name: 'RSA-OAEP',
          modulusLength: 2048,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          hash: { name: 'SHA-256' },
        },
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      )
    },

    deriveBitsFromPassphrase(passphrase, salt, bits) {
      if (typeof passphrase === 'string') {
        passphrase = new TextEncoder('utf-8').encode(passphrase)
      }
      if (typeof salt === 'string') {
        salt = new TextEncoder('utf-8').encode(salt)
      }
      return crypto
        .importKey(
          'raw',
          passphrase,
          {
            name: 'PBKDF2',
          },
          false,
          ['deriveBits']
        )
        .then(baseKey =>
          crypto.deriveBits(
            {
              name: 'PBKDF2',
              salt,
              iterations: 100000,
              hash: { name: 'SHA-256' },
            },
            baseKey,
            bits
          )
        )
        .then(bits => new Uint8Array(bits))
    },

    deriveKeyFromPassphrase(passphrase, salt) {
      if (typeof passphrase === 'string') {
        passphrase = new TextEncoder('utf-8').encode(passphrase)
      }
      if (typeof salt === 'string') {
        salt = new TextEncoder('utf-8').encode(salt)
      }

      return crypto
        .importKey(
          'raw',
          passphrase,
          {
            name: 'PBKDF2',
          },
          false,
          ['deriveKey']
        )
        .then(baseKey =>
          crypto.deriveKey(
            {
              name: 'PBKDF2',
              salt,
              iterations: 100000,
              hash: { name: 'SHA-256' },
            },
            baseKey,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
          )
        )
    },

    uInt8ArrayToB64(array) {
      return btoa(
        Array.from(array)
          .map(byte => String.fromCharCode(byte))
          .join('')
      )
    },

    b64ToUint8Array(b64) {
      return new Uint8Array(
        atob(b64)
          .split('')
          .map(c => c.charCodeAt(0))
      )
    },

    async generateAuthBits(passphrase, salt) {
      const bits = await exports.deriveBitsFromPassphrase(passphrase, salt, 512)
      return bits.slice(32, 32)
    },
  }

  let Cryptor = function() {
    return this
  }

  Cryptor.prototype = {
    async generate(passphrase, salt) {
      this.keyPair = await exports.generateKeypair()
      const bits = await exports.deriveBitsFromPassphrase(passphrase, salt, 512)
      this.masterKey = await crypto.importKey(
        'raw',
        bits.slice(0, 32).buffer,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      )
      this.authBits = bits.slice(32, 32)
    },

    async toJSON() {
      let privateKeyEncrypted = await crypto.exportKey(
        'pkcs8',
        this.keyPair.privateKey
      )
      privateKeyEncrypted = await exports.encryptSymmetric(
        privateKeyEncrypted,
        this.masterKey
      )

      // Convert to base64
      privateKeyEncrypted.ct = exports.uInt8ArrayToB64(privateKeyEncrypted.ct)
      privateKeyEncrypted.iv = exports.uInt8ArrayToB64(privateKeyEncrypted.iv)
      privateKeyEncrypted.additionalData = exports.uInt8ArrayToB64(
        privateKeyEncrypted.additionalData
      )

      return {
        privateKeyEncrypted,
        publicKey: await crypto.exportKey('jwk', this.keyPair.publicKey),
        authBits: this.authBits,
      }
    },

    async fromJSON(json, passphrase, salt) {
      const bits = await exports.deriveBitsFromPassphrase(passphrase, salt, 512)
      this.masterKey = await crypto.importKey(
        'raw',
        bits.slice(0, 32).buffer,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      )
      this.authBits = bits.slice(32, 32)
      let { privateKeyEncrypted, publicKey } = json

      let { ct, iv, additionalData } = privateKeyEncrypted
      ct = exports.b64ToUint8Array(ct)
      iv = exports.b64ToUint8Array(iv)
      additionalData = exports.b64ToUint8Array(additionalData)

      let privateKey = await exports.decryptSymmetric(
        ct,
        this.masterKey,
        iv,
        additionalData
      )

      privateKey = await crypto.importKey(
        'pkcs8',
        privateKey,
        {
          name: 'RSA-OAEP',
          modulusLength: 2048,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          hash: { name: 'SHA-256' },
        },
        true,
        ['decrypt', 'unwrapKey']
      )
      this.keyPair = { publicKey, privateKey }
    },
  }

  exports.Cryptor = Cryptor

  return exports
})
