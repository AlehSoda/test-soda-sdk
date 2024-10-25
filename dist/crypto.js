"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.HEX_BASE = exports.KEY_SIZE = exports.CT_SIZE = exports.FUNC_SIG_SIZE = exports.ADDRESS_SIZE = exports.BLOCK_SIZE = void 0;
exports.encrypt = encrypt;
exports.decrypt = decrypt;
exports.generateAesKey = generateAesKey;
exports.generateECDSAPrivateKey = generateECDSAPrivateKey;
exports.signIT = signIT;
exports.sign = sign;
exports.signEIP191 = signEIP191;
exports.prepareMessage = prepareMessage;
exports.prepareIT = prepareIT;
exports.generateRSAKeyPair = generateRSAKeyPair;
exports.encryptRSA = encryptRSA;
exports.decryptRSA = decryptRSA;
exports.getFuncSig = getFuncSig;
exports.encodeString = encodeString;
exports.reconstructUserKey = reconstructUserKey;
exports.aesEcbEncrypt = aesEcbEncrypt;
exports.decryptUint = decryptUint;
exports.encodeKey = encodeKey;
exports.decodeUint = decodeUint;
const node_forge_1 = __importDefault(require("node-forge"));
const ethers_1 = require("ethers");
exports.BLOCK_SIZE = 16; // AES block size in bytes
exports.ADDRESS_SIZE = 20; // 160-bit is the output of the Keccak-256 algorithm on the sender/contract address
exports.FUNC_SIG_SIZE = 4;
exports.CT_SIZE = 32;
exports.KEY_SIZE = 32;
exports.HEX_BASE = 16;
/**
 * Encrypts a plaintext using AES encryption with a given key.
 * @param {Buffer} key - The AES key (16 bytes).
 * @param {Buffer} plaintext - The plaintext to encrypt (must be 16 bytes or smaller).
 * @returns {Object} - An object containing the ciphertext and the random value 'r' used during encryption.
 * @throws {RangeError} - Throws if plaintext is larger than 16 bytes or if the key size is not 16 bytes.
 */
function encrypt(key, plaintext) {
    if (plaintext.length > exports.BLOCK_SIZE) {
        throw new RangeError("Plaintext size must be 128 bits or smaller.");
    }
    if (key.length !== exports.BLOCK_SIZE) {
        throw new RangeError("Key size must be 128 bits.");
    }
    // Create a new AES cipher using the provided key
    const r = node_forge_1.default.random.getBytesSync(exports.BLOCK_SIZE);
    const encryptedR = aesEcbEncrypt(r, key);
    const plaintext_padded = Buffer.concat([Buffer.alloc(exports.BLOCK_SIZE - plaintext.length), plaintext]);
    const ciphertext = Buffer.alloc(encryptedR.length);
    for (let i = 0; i < encryptedR.length; i++) {
        ciphertext[i] = encryptedR[i] ^ plaintext_padded[i];
    }
    const uint8ArrayR = new Uint8Array(r.split('').map(c => c.charCodeAt(0)));
    return { ciphertext, r: Buffer.from(uint8ArrayR) };
}
/**
 * Decrypts a ciphertext using AES decryption with a given key and random value 'r'.
 * @param {Buffer} key - The AES key (16 bytes).
 * @param {Buffer} r - The random value used during encryption (16 bytes).
 * @param {Buffer} ciphertext - The ciphertext to decrypt (16 bytes).
 * @returns {Uint8Array} - The decrypted plaintext.
 * @throws {RangeError} - Throws if any input size is incorrect.
 */
function decrypt(key, r, ciphertext) {
    // Ensure ciphertext size is 128 bits (16 bytes)
    if (ciphertext.length !== exports.BLOCK_SIZE) {
        throw new RangeError("Ciphertext size must be 128 bits.");
    }
    // Ensure key size is 128 bits (16 bytes)
    if (key.length !== exports.BLOCK_SIZE) {
        throw new RangeError("Key size must be 128 bits.");
    }
    // Ensure random value size is 128 bits (16 bytes)
    if (r.length !== exports.BLOCK_SIZE) {
        throw new RangeError("Random size must be 128 bits.");
    }
    const encryptedR = aesEcbEncrypt(r, key);
    const plaintext = new Uint8Array(exports.BLOCK_SIZE);
    for (let i = 0; i < encryptedR.length; i++) {
        plaintext[i] = encryptedR[i] ^ ciphertext[i];
    }
    return plaintext;
}
/**
 * Generates a random 128-bit AES key.
 * @returns {Buffer} - A Buffer containing a random 16-byte AES key.
 */
function generateAesKey() {
    const key = node_forge_1.default.random.getBytesSync(exports.BLOCK_SIZE);
    const uint8ArrayKey = new Uint8Array(key.split('').map(c => c.charCodeAt(0)));
    return Buffer.from(uint8ArrayKey);
}
/**
 * Generates a new ECDSA private key using the secp256k1 curve.
 * @returns {Buffer} - A Buffer containing a 32-byte private key.
 */
function generateECDSAPrivateKey() {
    // Generate a new random wallet
    const wallet = ethers_1.ethers.Wallet.createRandom();
    const privateKeyHex = wallet.privateKey;
    // Return the private key as a Buffer without the '0x' prefix
    return Buffer.from(privateKeyHex.slice(2), 'hex');
}
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
function signIT(sender, addr, funcSig, ct, key, eip191 = false) {
    if (sender.length !== exports.ADDRESS_SIZE) {
        throw new RangeError(`Invalid sender address length: ${sender.length} bytes, must be ${exports.ADDRESS_SIZE} bytes`);
    }
    if (addr.length !== exports.ADDRESS_SIZE) {
        throw new RangeError(`Invalid contract address length: ${addr.length} bytes, must be ${exports.ADDRESS_SIZE} bytes`);
    }
    if (funcSig.length !== exports.FUNC_SIG_SIZE) {
        throw new RangeError(`Invalid signature size: ${funcSig.length} bytes, must be ${exports.FUNC_SIG_SIZE} bytes`);
    }
    if (ct.length !== exports.CT_SIZE) {
        throw new RangeError(`Invalid ct length: ${ct.length} bytes, must be ${exports.CT_SIZE} bytes`);
    }
    if (key.length !== exports.KEY_SIZE) {
        throw new RangeError(`Invalid key length: ${key.length} bytes, must be ${exports.KEY_SIZE} bytes`);
    }
    // Create the message to be signed by concatenating all inputs
    let message = Buffer.concat([sender, addr, funcSig, ct]);
    if (eip191) {
        return signEIP191(message, key);
    }
    else {
        return sign(message, key);
    }
}
/**
 * Signs a message using the standard signing process.
 * @param {Buffer} message - The message to sign.
 * @param {Buffer} key - The signing key (32 bytes).
 * @returns {Buffer} - The signature as a concatenation of r, s, and v values.
 */
function sign(message, key) {
    const hash = ethers_1.ethers.keccak256(message);
    const signingKey = new ethers_1.ethers.SigningKey(key);
    const signature = signingKey.sign(hash);
    // Concatenate r, s, and v bytes
    return Buffer.concat([
        ethers_1.ethers.getBytes(signature.r),
        ethers_1.ethers.getBytes(signature.s),
        ethers_1.ethers.getBytes(`0x0${signature.v - 27}`)
    ]);
}
/**
 * Signs a message using EIP-191.
 * @param {Buffer} message - The message to sign.
 * @param {Buffer} key - The signing key (32 bytes).
 * @returns {Buffer} - The signature as a concatenation of r, s, and v values.
 */
function signEIP191(message, key) {
    const hash = ethers_1.ethers.hashMessage(message);
    const signingKey = new ethers_1.ethers.SigningKey(key);
    const signature = signingKey.sign(hash);
    // Concatenate r, s, and v bytes
    return Buffer.concat([
        ethers_1.ethers.getBytes(signature.r),
        ethers_1.ethers.getBytes(signature.s),
        ethers_1.ethers.getBytes(`0x0${signature.v - 27}`)
    ]);
}
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
function prepareMessage(plaintext, signerAddress, aesKey, contractAddress, functionSelector) {
    // Validate signerAddress (Ethereum address)
    if (!ethers_1.ethers.isAddress(signerAddress)) {
        throw new TypeError("Invalid signer address");
    }
    // Validate aesKey (32 bytes as hex string)
    if (typeof aesKey !== "string" || aesKey.length !== 32) {
        throw new TypeError("Invalid AES key length. Expected 32 bytes.");
    }
    // Validate contractAddress (Ethereum address)
    if (typeof contractAddress !== "string" || !ethers_1.ethers.isAddress(signerAddress)) {
        throw new TypeError("Invalid contract address");
    }
    // Validate functionSelector (4 bytes as hex string)
    if (typeof functionSelector !== "string" || functionSelector.length !== 10 || !functionSelector.startsWith('0x')) {
        throw new TypeError("Invalid function selector");
    }
    // Convert the plaintext to bytes
    const plaintextBytes = Buffer.alloc(8); // Allocate a buffer of size 8 bytes
    plaintextBytes.writeBigUInt64BE(plaintext); // Write the uint64 value to the buffer as little-endian
    // Encrypt the plaintext using AES key
    const { ciphertext, r } = encrypt(Buffer.from(aesKey, 'hex'), plaintextBytes);
    const ct = Buffer.concat([ciphertext, r]);
    // Create the packed message
    const message = ethers_1.ethers.solidityPacked(["address", "address", "bytes4", "uint256"], [signerAddress, contractAddress, functionSelector, BigInt("0x" + ct.toString("hex"))]);
    // Convert the ciphertext to BigInt
    const encryptedInt = BigInt("0x" + ct.toString("hex"));
    return { encryptedInt, message };
}
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
function prepareIT(plaintext, userAesKey, sender, contract, hashFunc, signingKey, eip191 = false) {
    // Get the bytes of the sender, contract, and function signature
    // todo: check if sender and contract are already in bytes
    const senderBytes = sender;
    const contractBytes = contract;
    // Convert the plaintext to bytes
    const plaintextBytes = Buffer.alloc(8); // Allocate a buffer of size 8 bytes
    plaintextBytes.writeBigUInt64BE(BigInt(plaintext)); // Write the uint64 value to the buffer as little-endian
    // Encrypt the plaintext using AES key
    const { ciphertext, r } = encrypt(userAesKey, plaintextBytes);
    let ct = Buffer.concat([ciphertext, r]);
    // Sign the message
    const signature = signIT(senderBytes, contractBytes, hashFunc, ct, signingKey, eip191);
    // Convert the ciphertext to BigInt
    const ctInt = BigInt('0x' + ct.toString('hex'));
    return { ctInt, signature };
}
/**
 * Generates a new RSA key pair.
 * @returns {Object} - An object containing the private key and public key as Buffers.
 */
function generateRSAKeyPair() {
    // Generate a new RSA key pair with 2048 bits
    const rsaKeyPair = node_forge_1.default.pki.rsa.generateKeyPair({ bits: 2048 });
    // Convert the private and public keys to DER format
    const privateKey = node_forge_1.default.asn1.toDer(node_forge_1.default.pki.privateKeyToAsn1(rsaKeyPair.privateKey)).data;
    // Convert the public key to DER format
    const publicKey = node_forge_1.default.asn1.toDer(node_forge_1.default.pki.publicKeyToAsn1(rsaKeyPair.publicKey)).data;
    // Return the private and public keys as Buffers
    return {
        privateKey: Buffer.from(encodeString(privateKey)),
        publicKey: Buffer.from(encodeString(publicKey))
    };
}
/**
 * Encrypts plaintext using RSA with the provided public key.
 * @param {Uint8Array} publicKeyUint8Array - The RSA public key in Uint8Array format.
 * @param {string} plaintext - The plaintext to be encrypted.
 * @returns {Uint8Array} - The encrypted data as a Uint8Array.
 * @throws {Error} - Throws if the encryption fails or if the input format is incorrect.
 */
function encryptRSA(publicKeyUint8Array, plaintext) {
    // Convert the Uint8Array to a binary string for forge
    const binaryDerString = String.fromCharCode(...publicKeyUint8Array);
    // Decode the binary DER string into an ASN.1 object
    const asn1PublicKey = node_forge_1.default.asn1.fromDer(binaryDerString);
    // Convert the ASN.1 object to an RSA public key
    const forgePublicKey = node_forge_1.default.pki.publicKeyFromAsn1(asn1PublicKey);
    // Encrypt the plaintext using RSA-OAEP with SHA-256 as the hash function
    const encrypted = forgePublicKey.encrypt(plaintext, 'RSA-OAEP', {
        md: node_forge_1.default.md.sha256.create() // Use SHA-256 for OAEP padding
    });
    // Convert the encrypted binary string to a Uint8Array
    return new Uint8Array(node_forge_1.default.util.createBuffer(encrypted, 'raw').bytes().split('').map(c => c.charCodeAt(0)));
}
/**
 * Decrypts RSA-encrypted data using the provided private key.
 * @param {Uint8Array} privateKey - The RSA private key in Uint8Array format.
 * @param {Uint8Array|string} ciphertext - The encrypted data to decrypt (Uint8Array or hex string).
 * @returns {Uint8Array} - The decrypted plaintext as a Uint8Array.
 * @throws {Error} - Throws if the decryption fails or if the input format is incorrect.
 */
function decryptRSA(privateKey, ciphertext) {
    // Convert privateKey from Uint8Array to PEM format
    const privateKeyPEM = node_forge_1.default.pki.privateKeyToPem(node_forge_1.default.pki.privateKeyFromAsn1(node_forge_1.default.asn1.fromDer(node_forge_1.default.util.createBuffer(privateKey))));
    // Decrypt using RSA-OAEP
    const rsaPrivateKey = node_forge_1.default.pki.privateKeyFromPem(privateKeyPEM);
    const decrypted = rsaPrivateKey.decrypt(node_forge_1.default.util.hexToBytes(ciphertext), 'RSA-OAEP', {
        md: node_forge_1.default.md.sha256.create()
    });
    return encodeString(decrypted);
}
/**
 * Generates the function selector for a given function signature.
 * @param {string} functionSig - The function signature (e.g., 'test(bytes)').
 * @returns {Buffer} - A Buffer containing the first 4 bytes of the Keccak-256 hash of the function signature.
 */
function getFuncSig(functionSig) {
    const functionSelector = ethers_1.ethers.id(functionSig).slice(0, 10);
    return Buffer.from(functionSelector.slice(2, 10), 'hex');
}
/**
 * Encodes a string into a Uint8Array of hexadecimal values.
 * @param {string} str - The input string to encode.
 * @returns {Uint8Array} - A Uint8Array representing the encoded hexadecimal values of the input string.
 */
function encodeString(str) {
    return new Uint8Array([...str.split('').map((char) => parseInt(char.codePointAt(0)?.toString(exports.HEX_BASE), exports.HEX_BASE))]);
}
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
function reconstructUserKey(privateKey, encryptedKeyShare0, encryptedKeyShare1) {
    const decryptedKeyShare0 = decryptRSA(privateKey, encryptedKeyShare0);
    const decryptedKeyShare1 = decryptRSA(privateKey, encryptedKeyShare1);
    const aesKey = Buffer.alloc(decryptedKeyShare0.length);
    for (let i = 0; i < decryptedKeyShare0.length; i++) {
        aesKey[i] = decryptedKeyShare0[i] ^ decryptedKeyShare1[i];
    }
    return aesKey;
}
/**
 * Encrypts a random value 'r' using AES in ECB mode with the provided key.
 * @param {string} r - The random value to be encrypted (16 bytes).
 * @param {Buffer} key - The AES key (16 bytes).
 * @returns {Uint8Array} - A Uint8Array containing the encrypted random value.
 * @throws {RangeError} - Throws if the key size is not 16 bytes.
 */
function aesEcbEncrypt(r, key) {
    // Ensure key size is 128 bits (16 bytes)
    if (key.length != exports.BLOCK_SIZE) {
        throw new RangeError("Key size must be 128 bits.");
    }
    // Create a new AES cipher using the provided key
    const cipher = node_forge_1.default.cipher.createCipher('AES-ECB', node_forge_1.default.util.createBuffer(key));
    // Encrypt the random value 'r' using AES in ECB mode
    cipher.start();
    cipher.update(node_forge_1.default.util.createBuffer(r));
    cipher.finish();
    // Get the encrypted random value 'r' as a Buffer and ensure it's exactly 16 bytes
    const encryptedR = encodeString(cipher.output.data).slice(0, exports.BLOCK_SIZE);
    return encryptedR;
}
function decryptUint(ciphertext, userKey) {
    // Convert ciphertext to Uint8Array
    let ctArray = new Uint8Array();
    while (ciphertext > 0) {
        const temp = new Uint8Array([Number(ciphertext & BigInt(255))]);
        ctArray = new Uint8Array([...temp, ...ctArray]);
        ciphertext >>= BigInt(8);
    }
    ctArray = new Uint8Array([...new Uint8Array(32 - ctArray.length), ...ctArray]);
    // Split CT into two 128-bit arrays r and cipher
    const cipher = ctArray.subarray(0, exports.BLOCK_SIZE);
    const r = ctArray.subarray(exports.BLOCK_SIZE);
    const userKeyBytes = encodeKey(userKey);
    // Decrypt the cipher
    const decryptedMessage = decrypt(userKeyBytes, r, cipher);
    return decodeUint(decryptedMessage);
}
function encodeKey(userKey) {
    const keyBytes = new Uint8Array(16);
    for (let i = 0; i < 32; i += 2) {
        keyBytes[i / 2] = parseInt(userKey.slice(i, i + 2), exports.HEX_BASE);
    }
    return keyBytes;
}
function decodeUint(plaintextBytes) {
    const plaintext = [];
    let byte = '';
    for (let i = 0; i < plaintextBytes.length; i++) {
        byte = plaintextBytes[i].toString(exports.HEX_BASE).padStart(2, '0'); // ensure that the zero byte is represented using two digits
        plaintext.push(byte);
    }
    return BigInt("0x" + plaintext.join(""));
}
