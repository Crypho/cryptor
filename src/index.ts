// Helper to extract argument types from a function
type ArgumentsType<T> = T extends (...args: infer A) => any ? A : never;

  interface IJSONCryptoKey {
    ct: Uint8Array
    iv: Uint8Array
    additionalData: Uint8Array
  }

  interface IBase64JSONCryptoKey {
    ct: string
    iv: string
    additionalData: string
  }
  
  /**
   * JSON representation of a key pair.
   * 
   * This structured is designed to be transmitted. The private key is encrypted.
   */
  interface ICryptorKeyPair {
    privateKeyEncrypted: IBase64JSONCryptoKey,
    publicKey: JsonWebKey,
    authBits: Uint8Array,
  }

  const MASTER_KEY_USAGES: KeyUsage[] = ['encrypt', 'decrypt']
  const MASTER_KEY_ALGORITHM: AesKeyAlgorithm = { name: 'AES-GCM', length: 256 }

  const SYMMETRIC_KEY_PARAMETERS = {
      name: 'AES-GCM',
      tagLength: 128,
  }
  const ASYMMETRIC_KEY_USAGES: KeyUsage[] = ['wrapKey', 'unwrapKey']
  const ASYMMETRIC_KEY_ALGORITHM: RsaHashedKeyAlgorithm = {
    name: 'RSA-OAEP',
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: { name: 'SHA-256' },
  }

  const KEY_WRAP_ALGORITHM: RsaHashedKeyAlgorithm = {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: { name: 'SHA-256' },
  }

  /**
   * Convert input to UTF-8 encoded Uint8Array
   * 
   * @param input Data to convert. If this is a string it is UTF-8 encoded.
   */
  const toUint8Array = (input: string | Uint8Array): Uint8Array => typeof input === 'string' ? new TextEncoder().encode(input) : input


  export function generateSymmetricKey() {
      return crypto.subtle.generateKey(
        {
          name: 'AES-GCM',
          length: 256,
        },
        true, // make key extractable
        ['encrypt', 'decrypt']
      )
    }

    export function encryptSymmetric(pt: string | Uint8Array, key: CryptoKey): PromiseLike<IJSONCryptoKey> {
      const iv = crypto.getRandomValues(new Uint8Array(12))
      const additionalData = crypto.getRandomValues(new Uint8Array(12))
      return crypto.subtle.encrypt(
          {
            ...SYMMETRIC_KEY_PARAMETERS,
            iv,
            additionalData,
          } as AesGcmParams,
          key,
          toUint8Array(pt)
        )
        .then(ct => {
          return {
            ct: new Uint8Array(ct),
            iv,
            additionalData,
          }
        })
    }

    export function decryptSymmetric(ct: ArgumentsType<SubtleCrypto['decrypt']>[2], key: CryptoKey, iv: AesGcmParams['iv'], additionalData: AesGcmParams['additionalData']) {
      return crypto.subtle.decrypt(
        {
          ...SYMMETRIC_KEY_PARAMETERS,
          iv,
          additionalData,
        } as AesGcmParams,
        key,
        ct
      )
    }

    export function generateKeypair() {
      return crypto.subtle.generateKey(ASYMMETRIC_KEY_ALGORITHM,
        true, // make key extractable
        ASYMMETRIC_KEY_USAGES,
      )
    }

    export function wrapKey(key: CryptoKey, publicKey: CryptoKey) {
      return crypto.subtle.wrapKey('raw', key, publicKey, KEY_WRAP_ALGORITHM)
    }

    export function unwrapKey(wrapped: ArgumentsType<SubtleCrypto['unwrapKey']>[1], privateKey: CryptoKey) {
      return crypto.subtle.unwrapKey(
        'raw',
        wrapped,
        privateKey,
        KEY_WRAP_ALGORITHM,
        MASTER_KEY_ALGORITHM,
        true,
        MASTER_KEY_USAGES
      )
    }

    export function deriveBitsFromPassphrase(passphrase: string | Uint8Array, salt: string | Uint8Array, bits: number) {
      return crypto.subtle.importKey(
          'raw',
          toUint8Array(passphrase),
          {
            name: 'PBKDF2',
          } as Pbkdf2Params,
          false,
          ['deriveBits']
        )
        .then(baseKey =>
          crypto.subtle.deriveBits(
            {
              name: 'PBKDF2',
              salt: toUint8Array(salt),
              iterations: 100000,
              hash: { name: 'SHA-256' },
            } as Pbkdf2Params,
            baseKey,
            bits
          )
        )
        .then(bits => new Uint8Array(bits))
    }

    export function deriveKeyFromPassphrase(passphrase: string | Uint8Array, salt: string | Uint8Array) {
      return crypto.subtle.importKey(
          'raw',
          toUint8Array(passphrase),
          {
            name: 'PBKDF2',
          } as Pbkdf2Params,
          false,
          ['deriveKey']
        )
        .then(baseKey =>
          crypto.subtle.deriveKey(
            {
              name: 'PBKDF2',
              salt: toUint8Array(salt),
              iterations: 100000,
              hash: { name: 'SHA-256' },
            } as Pbkdf2Params,
            baseKey,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
          )
        )
    }

    export function uInt8ArrayToB64(array: Uint8Array) {
      return btoa(
        Array.from(array)
          .map(byte => String.fromCharCode(byte))
          .join('')
      )
    }

    export function b64ToUint8Array(b64: string) {
      return new Uint8Array(
        atob(b64)
          .split('')
          .map(c => c.charCodeAt(0))
      )
    }

    export async function generateAuthBits(passphrase: string | Uint8Array, salt: string | Uint8Array) {
      const bits = await deriveBitsFromPassphrase(passphrase, salt, 512)
      return bits.slice(32, 32)
    }

export class Cryptor {
  public authBits: Uint8Array
  public keyPair: CryptoKeyPair
  public masterKey: CryptoKey

    async generate(passphrase: string | Uint8Array, salt: string | Uint8Array) {
      this.keyPair = await generateKeypair()
      const bits = await deriveBitsFromPassphrase(passphrase, salt, 512)
      this.masterKey = await crypto.subtle.importKey(
        'raw',
        bits.slice(0, 32).buffer,
        MASTER_KEY_ALGORITHM,
        true,
        MASTER_KEY_USAGES
      )
      this.authBits = bits.slice(32, 32)
    }

    async toJSON(): Promise<ICryptorKeyPair> {
      const key = await crypto.subtle.exportKey(
        'pkcs8',
        this.keyPair.privateKey
      ) as Uint8Array

      const privateKeyEncrypted = await encryptSymmetric(
        key,
        this.masterKey
      )

      const b64Key: IBase64JSONCryptoKey = {
        ct: uInt8ArrayToB64(privateKeyEncrypted.ct),
        iv: uInt8ArrayToB64(privateKeyEncrypted.iv),
        additionalData: uInt8ArrayToB64(
          privateKeyEncrypted.additionalData
        ),
      }

      return {
        privateKeyEncrypted: b64Key,
        publicKey: await crypto.subtle.exportKey('jwk', this.keyPair.publicKey),
        authBits: this.authBits,
      }
    }

    async fromJSON(json: ICryptorKeyPair, passphrase: string | Uint8Array, salt: string | Uint8Array) {
      const bits = await deriveBitsFromPassphrase(passphrase, salt, 512)
      this.masterKey = await crypto.subtle.importKey(
        'raw',
        bits.slice(0, 32).buffer,
        MASTER_KEY_ALGORITHM,
        true,
        MASTER_KEY_USAGES
      )
      this.authBits = bits.slice(32, 32)
      let { privateKeyEncrypted } = json

      const ct = b64ToUint8Array(privateKeyEncrypted.ct)
      const iv = b64ToUint8Array(privateKeyEncrypted.iv)
      const additionalData = b64ToUint8Array(privateKeyEncrypted.additionalData)

      const decryptedKey = await decryptSymmetric(
        ct,
        this.masterKey,
        iv,
        additionalData
      )

      const publicKey = await  crypto.subtle.importKey("jwk", json.publicKey, ASYMMETRIC_KEY_ALGORITHM, true, [])
      const privateKey = await crypto.subtle.importKey(
        'pkcs8',
        decryptedKey,
        ASYMMETRIC_KEY_ALGORITHM as RsaHashedImportParams,
        true,
        ['decrypt', 'unwrapKey'],
      )
      this.keyPair = { publicKey, privateKey }
    }
  }