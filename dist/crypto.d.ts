export declare const BLOCK_SIZE = 16;
export declare const ADDRESS_SIZE = 20;
export declare const FUNC_SIG_SIZE = 4;
export declare const CT_SIZE = 32;
export declare const KEY_SIZE = 32;
export declare const HEX_BASE = 16;
/**
 * Encrypts a plaintext using AES encryption with a given key.
 * @param {Buffer} key - The AES key (16 bytes).
 * @param {Buffer} plaintext - The plaintext to encrypt (must be 16 bytes or smaller).
 * @returns {Object} - An object containing the ciphertext and the random value 'r' used during encryption.
 * @throws {RangeError} - Throws if plaintext is larger than 16 bytes or if the key size is not 16 bytes.
 */
export declare function encrypt(key: Uint8Array, plaintext: Uint8Array): {
    ciphertext: Buffer;
    r: Buffer;
};
/**
 * Decrypts a ciphertext using AES decryption with a given key and random value 'r'.
 * @param {Buffer} key - The AES key (16 bytes).
 * @param {Buffer} r - The random value used during encryption (16 bytes).
 * @param {Buffer} ciphertext - The ciphertext to decrypt (16 bytes).
 * @returns {Uint8Array} - The decrypted plaintext.
 * @throws {RangeError} - Throws if any input size is incorrect.
 */
export declare function decrypt(key: Uint8Array, r: Uint8Array, ciphertext: Uint8Array): Uint8Array;
/**
 * Generates a random 128-bit AES key.
 * @returns {Buffer} - A Buffer containing a random 16-byte AES key.
 */
export declare function generateAesKey(): Buffer;
/**
 * Generates a new ECDSA private key using the secp256k1 curve.
 * @returns {Buffer} - A Buffer containing a 32-byte private key.
 */
export declare function generateECDSAPrivateKey(): Buffer;
/**
 * Signs a message using the provided parameters and a given key.
 * Supports optional EIP-191 signing.
 * @param {Buffer} sender - The sender's address (20 bytes).
 * @param {Buffer} addr - The contract address (20 bytes).
 * @param {Buffer} funcSig - The function signature (4 bytes).
 * @param {Buffer} ct - The ciphertext (32 bytes).
 * @param {Buffer} key - The signing key (32 bytes).
 * @param {boolean} eip191 - Whether to use EIP-191 signing (default: false).
 * @returns {Buffer} - The signature as a Buffer.
 * @throws {RangeError} - Throws if input sizes are incorrect.
 */
export declare function signIT(sender: Buffer, addr: Buffer, funcSig: Buffer, ct: Buffer, key: Buffer, eip191?: boolean): Buffer;
/**
 * Signs a message using the standard signing process.
 * @param {Buffer} message - The message to sign.
 * @param {Buffer} key - The signing key (32 bytes).
 * @returns {Buffer} - The signature as a concatenation of r, s, and v values.
 */
export declare function sign(message: Buffer, key: Buffer): Buffer;
/**
 * Signs a message using EIP-191.
 * @param {Buffer} message - The message to sign.
 * @param {Buffer} key - The signing key (32 bytes).
 * @returns {Buffer} - The signature as a concatenation of r, s, and v values.
 */
export declare function signEIP191(message: Buffer, key: Buffer): Buffer;
/**
 * Prepares a message by encrypting the given plaintext and constructing the message. This message needs to be signed to create an IT.
 * @param {bigint} plaintext - The plaintext value to be encrypted as a BigInt.
 * @param {string} signerAddress - The address of the signer (Ethereum address).
 * @param {string} aesKey - The AES key used for encryption (32 bytes as a hex string).
 * @param {string} contractAddress - The address of the contract (Ethereum address).
 * @param {string} functionSelector - The function selector (4 bytes as a hex string, e.g., '0x12345678').
 * @returns {Object} - An object containing the encrypted integer and the message.
 * @throws {TypeError} - Throws if any of the input parameters are of invalid types or have incorrect lengths.
 */
export declare function prepareMessage(plaintext: bigint, signerAddress: string, aesKey: string, contractAddress: string, functionSelector: string): {
    encryptedInt: bigint;
    message: string;
};
/**
 * Prepares an IT by encrypting the plaintext, signing the encrypted message,
 * and packaging the resulting data. This data represents encrypted data that can be sent to the contract.
 * @param {bigint} plaintext - The plaintext value to be encrypted as a BigInt.
 * @param {Buffer} userAesKey - The AES key used for encryption (16 bytes).
 * @param {Buffer} sender - The sender's address as a Buffer.
 * @param {Buffer} contract - The contract's address as a Buffer.
 * @param {Buffer} hashFunc - The function signature (4 bytes).
 * @param {Buffer} signingKey - The ECDSA signing key (32 bytes).
 * @param {boolean} [eip191=false] - Whether to use EIP-191 signing (default: false).
 * @returns {Object} - An object containing the encrypted integer (as `ctInt`) and the signature.
 */
export declare function prepareIT(plaintext: bigint, userAesKey: Buffer, sender: Buffer, contract: Buffer, hashFunc: Buffer, signingKey: Buffer, eip191?: boolean): {
    ctInt: bigint;
    signature: Buffer;
};
/**
 * Generates a new RSA key pair.
 * @returns {Object} - An object containing the private key and public key as Buffers.
 */
export declare function generateRSAKeyPair(): {
    privateKey: Buffer;
    publicKey: Buffer;
};
/**
 * Encrypts plaintext using RSA with the provided public key.
 * @param {Uint8Array} publicKeyUint8Array - The RSA public key in Uint8Array format.
 * @param {string} plaintext - The plaintext to be encrypted.
 * @returns {Uint8Array} - The encrypted data as a Uint8Array.
 * @throws {Error} - Throws if the encryption fails or if the input format is incorrect.
 */
export declare function encryptRSA(publicKeyUint8Array: Uint8Array, plaintext: string): Uint8Array;
/**
 * Decrypts RSA-encrypted data using the provided private key.
 * @param {Uint8Array} privateKey - The RSA private key in Uint8Array format.
 * @param {Uint8Array|string} ciphertext - The encrypted data to decrypt (Uint8Array or hex string).
 * @returns {Uint8Array} - The decrypted plaintext as a Uint8Array.
 * @throws {Error} - Throws if the decryption fails or if the input format is incorrect.
 */
export declare function decryptRSA(privateKey: Uint8Array, ciphertext: string): Uint8Array;
/**
 * Generates the function selector for a given function signature.
 * @param {string} functionSig - The function signature (e.g., 'test(bytes)').
 * @returns {Buffer} - A Buffer containing the first 4 bytes of the Keccak-256 hash of the function signature.
 */
export declare function getFuncSig(functionSig: string): Buffer;
/**
 * Encodes a string into a Uint8Array of hexadecimal values.
 * @param {string} str - The input string to encode.
 * @returns {Uint8Array} - A Uint8Array representing the encoded hexadecimal values of the input string.
 */
export declare function encodeString(str: string): Uint8Array;
/**
 * This function recovers a user's key by decrypting two encrypted key shares with the given private key,
 * and then XORing the two key shares together.
 *
 * @param {Buffer} privateKey - The private key used to decrypt the key shares.
 * @param {string} encryptedKeyShare0 - The first encrypted key share.
 * @param {string} encryptedKeyShare1 - The second encrypted key share.
 *
 * @returns {Buffer} - The recovered user key.
 */
export declare function reconstructUserKey(privateKey: Buffer, encryptedKeyShare0: string, encryptedKeyShare1: string): Buffer;
/**
 * Encrypts a random value 'r' using AES in ECB mode with the provided key.
 * @param {string} r - The random value to be encrypted (16 bytes).
 * @param {Buffer} key - The AES key (16 bytes).
 * @returns {Uint8Array} - A Uint8Array containing the encrypted random value.
 * @throws {RangeError} - Throws if the key size is not 16 bytes.
 */
export declare function aesEcbEncrypt(r: string | Uint8Array, key: Uint8Array): Uint8Array;
export declare function decryptUint(ciphertext: bigint, userKey: string): bigint;
export declare function encodeKey(userKey: string): Uint8Array;
export declare function decodeUint(plaintextBytes: Uint8Array): bigint;
