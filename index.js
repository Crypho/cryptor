;((root, factory) => {
  if (typeof define === 'function' && define.amd) {
    // AMD
    define([], factory)
  } else if (typeof exports === 'object') {
    // Node, CommonJS-like
    module.exports = factory()
  } else {
    // Browser globals (root is window)
    root.snitch = factory()
  }
})(this, () => {
  const exports = {
    generateSymmetricKey() {
      return window.crypto.subtle.generateKey(
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
      return window.crypto.subtle
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
      return window.crypto.subtle.decrypt(
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
  }

  return exports
})
