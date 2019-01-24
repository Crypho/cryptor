declare type ArgumentsType<T> = T extends (...args: infer A) => any ? A : never;
interface IJSONCryptoKey {
    ct: Uint8Array;
    iv: Uint8Array;
    additionalData: Uint8Array;
}
interface IBase64JSONCryptoKey {
    ct: string;
    iv: string;
    additionalData: string;
}
/**
 * JSON representation of a key pair.
 *
 * This structured is designed to be transmitted. The private key is encrypted.
 */
interface ICryptorKeyPair {
    privateKeyEncrypted: IBase64JSONCryptoKey;
    publicKey: JsonWebKey;
    authBits: Uint8Array;
}
export declare function generateSymmetricKey(): PromiseLike<CryptoKey>;
export declare function encryptSymmetric(pt: string | Uint8Array, key: CryptoKey): PromiseLike<IJSONCryptoKey>;
export declare function decryptSymmetric(ct: ArgumentsType<SubtleCrypto['decrypt']>[2], key: CryptoKey, iv: AesGcmParams['iv'], additionalData: AesGcmParams['additionalData']): PromiseLike<ArrayBuffer>;
export declare function generateKeypair(): PromiseLike<CryptoKeyPair>;
export declare function wrapKey(key: CryptoKey, publicKey: CryptoKey): PromiseLike<ArrayBuffer>;
export declare function unwrapKey(wrapped: ArgumentsType<SubtleCrypto['unwrapKey']>[1], privateKey: CryptoKey): PromiseLike<CryptoKey>;
export declare function deriveBitsFromPassphrase(passphrase: string | Uint8Array, salt: string | Uint8Array, bits: number): PromiseLike<Uint8Array>;
export declare function deriveKeyFromPassphrase(passphrase: string | Uint8Array, salt: string | Uint8Array): PromiseLike<CryptoKey>;
export declare function uInt8ArrayToB64(array: Uint8Array): string;
export declare function b64ToUint8Array(b64: string): Uint8Array;
export declare function generateAuthBits(passphrase: string | Uint8Array, salt: string | Uint8Array): Promise<Uint8Array>;
export declare class Cryptor {
    authBits: Uint8Array;
    keyPair: CryptoKeyPair;
    masterKey: CryptoKey;
    generate(passphrase: string | Uint8Array, salt: string | Uint8Array): Promise<void>;
    toJSON(): Promise<ICryptorKeyPair>;
    fromJSON(json: ICryptorKeyPair, passphrase: string | Uint8Array, salt: string | Uint8Array): Promise<void>;
}
export {};
