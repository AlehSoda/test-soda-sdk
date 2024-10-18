import { Buffer } from 'buffer';

export const BLOCK_SIZE: number;
export const ADDRESS_SIZE: number;
export const FUNC_SIG_SIZE: number;
export const CT_SIZE: number;
export const KEY_SIZE: number;
export const HEX_BASE: number;

export interface EncryptedData {
    ciphertext: Buffer;
    r: Buffer;
}

export function encrypt(key: Buffer, plaintext: Buffer): EncryptedData;
export function decrypt(key: Buffer, r: Buffer, ciphertext: Buffer): Uint8Array;
export function generateAesKey(): Buffer;
export function generateECDSAPrivateKey(): Buffer;
export function signIT(
    sender: Buffer,
    addr: Buffer,
    funcSig: Buffer,
    ct: Buffer,
    key: Buffer,
    eip191?: boolean
): Buffer;
export function sign(message: Buffer, key: Buffer): Buffer;
export function signEIP191(message: Buffer, key: Buffer): Buffer;

export interface PreparedMessage {
    encryptedInt: bigint;
    message: string;
}

export function prepareMessage(
    plaintext: bigint,
    signerAddress: string,
    aesKey: string,
    contractAddress: string,
    functionSelector: string
): PreparedMessage;

export interface PreparedIT {
    ctInt: bigint;
    signature: Buffer;
}

export function prepareIT(
    plaintext: bigint,
    userAesKey: Buffer,
    sender: Buffer,
    contract: Buffer,
    hashFunc: Buffer,
    signingKey: Buffer,
    eip191?: boolean
): PreparedIT;

export interface RSAKeyPair {
    privateKey: Buffer;
    publicKey: Buffer;
}

export function generateRSAKeyPair(): RSAKeyPair;
export function encryptRSA(publicKeyUint8Array: Uint8Array, plaintext: string): Uint8Array;
export function decryptRSA(privateKeyUint8Array: Uint8Array, ciphertext: Uint8Array | string): Uint8Array;
export function getFuncSig(functionSig: string): Buffer;
export function encodeString(str: string): Uint8Array;
export function encryptNumber(r: string, key: Buffer): Uint8Array;
