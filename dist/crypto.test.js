"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("./crypto");
const fs_1 = __importDefault(require("fs"));
const crypto_2 = __importDefault(require("crypto"));
const utills_1 = require("./utills");
const ethereumjs_util_1 = require("ethereumjs-util");
const ethers_1 = require("ethers");
const assert = __importStar(require("node:assert"));
function extractSignatureComponents(signatureBytes) {
    // Allocate buffers for r, s, and v
    let rBytes = Buffer.alloc(32);
    let sBytes = Buffer.alloc(32);
    let vByte = Buffer.alloc(1);
    // Copy the corresponding bytes from the signature
    signatureBytes.copy(rBytes, 0, 0, 32);
    signatureBytes.copy(sBytes, 0, 32, 64);
    signatureBytes.copy(vByte, 0, 64);
    // Return the components as an object
    return { rBytes, sBytes, vByte };
}
function uint8ArrayToBigInt(uint8Array) {
    let value = BigInt(0);
    for (let i = 0; i < uint8Array.length; i++) {
        value = (value << 8n) | BigInt(uint8Array[i]);
    }
    return value;
}
describe('Crypto Tests', () => {
    // Test case for encrypt and decrypt
    it('should encrypt and decrypt successfully', () => {
        // Arrange
        const plaintextInteger = 100;
        const plaintextBuffer = Buffer.alloc(1);
        plaintextBuffer.writeUInt8(plaintextInteger);
        // Act
        const key = (0, crypto_1.generateAesKey)();
        const { ciphertext, r } = (0, crypto_1.encrypt)(key, plaintextBuffer);
        const decryptedBuffer = (0, crypto_1.decrypt)(key, r, ciphertext);
        // Write Buffer to file to later check in Go
        fs_1.default.writeFileSync("test_jsEncryption.txt", key.toString('hex') + "\n" + ciphertext.toString('hex') + "\n" + r.toString('hex'));
        const decryptedInteger = uint8ArrayToBigInt(decryptedBuffer);
        // Assert
        assert.strictEqual(decryptedInteger, BigInt(plaintextInteger));
    });
    // Test case for load and write AES key
    it('should load and write AES key successfully', () => {
        // Arrange
        const key = (0, crypto_1.generateAesKey)();
        // Act
        (0, utills_1.writeAesKey)('key.txt', key);
        const loadedKey = (0, utills_1.loadAesKey)('key.txt');
        // Assert
        assert.deepStrictEqual(loadedKey, key);
        // Delete the key file
        fs_1.default.unlink('key.txt', (err) => {
            if (err) {
                console.error('Error deleting file:', err);
            }
        });
    });
    // Test case for invalid plaintext size
    it('should throw error for invalid plaintext size', () => {
        // Arrange
        const key = (0, crypto_1.generateAesKey)();
        const plaintextBuffer = Buffer.alloc(20); // Bigger than 128 bits
        // Act and Assert
        assert.throws(() => (0, crypto_1.encrypt)(key, plaintextBuffer), RangeError);
    });
    // Test case for invalid ciphertext size
    it('should throw error for invalid ciphertext size', () => {
        // Arrange
        const key = (0, crypto_1.generateAesKey)();
        const ciphertext = Buffer.from([0x01, 0x02, 0x03]); // Smaller than 128 bits
        const r = Buffer.alloc(crypto_1.BLOCK_SIZE);
        // Act and Assert
        assert.throws(() => (0, crypto_1.decrypt)(key, r, ciphertext), RangeError);
    });
    // Test case for invalid random size
    it('should throw error for invalid random size', () => {
        // Arrange
        const key = (0, crypto_1.generateAesKey)();
        const r = Buffer.from([0x01, 0x02, 0x03]); // Smaller than 128 bits
        const ciphertext = Buffer.alloc(crypto_1.BLOCK_SIZE);
        // Act and Assert
        assert.throws(() => (0, crypto_1.decrypt)(key, r, ciphertext), RangeError);
    });
    // Test case for invalid key size
    it('should throw error for invalid key size', () => {
        // Arrange
        const key = Buffer.from([0x01, 0x02, 0x03]); // Smaller than 128 bits
        // Act and Assert
        // Test invalid key size when writing key
        assert.throws(() => (0, utills_1.writeAesKey)('key.txt', key), RangeError);
        // Test invalid key size when encrypting
        const plaintextBuffer = Buffer.alloc(crypto_1.BLOCK_SIZE);
        assert.throws(() => (0, crypto_1.encrypt)(key, plaintextBuffer), RangeError);
        // Test invalid key size when decrypting
        const ciphertext = Buffer.alloc(crypto_1.BLOCK_SIZE);
        const r = Buffer.alloc(crypto_1.BLOCK_SIZE);
        assert.throws(() => (0, crypto_1.decrypt)(key, r, ciphertext), RangeError);
    });
    // Test case for verify signature
    it('should sign and verify the signature', () => {
        // Arrange
        // Simulate the generation of random bytes
        const sender = crypto_2.default.randomBytes(crypto_1.ADDRESS_SIZE);
        const addr = crypto_2.default.randomBytes(crypto_1.ADDRESS_SIZE);
        const funcSig = crypto_2.default.randomBytes(crypto_1.FUNC_SIG_SIZE);
        let key = (0, crypto_1.generateECDSAPrivateKey)();
        // Create a ciphertext
        const plaintextBuffer = Buffer.alloc(1);
        plaintextBuffer.writeUInt8(100);
        const aeskey = (0, crypto_1.generateAesKey)();
        const { ciphertext, r } = (0, crypto_1.encrypt)(aeskey, plaintextBuffer);
        let ct = Buffer.concat([ciphertext, r]);
        // Act
        // Generate the signature
        const signatureBytes = (0, crypto_1.signIT)(sender, addr, funcSig, ct, key);
        const { rBytes, sBytes, vByte } = extractSignatureComponents(signatureBytes);
        // Convert v buffer back to integer
        let v = vByte.readUInt8();
        // JS expects v to be 27 or 28. But in Ethereum, v is either 0 or 1.
        // In the sign function, 27 is subtracted from v in order to make it work with ethereum.
        // Now 27 should be added back to v to make it work with JS veification.
        if (v !== 27 && v !== 28) {
            v += 27;
        }
        // Verify the signature
        const expectedPublicKey = (0, ethereumjs_util_1.privateToPublic)(key);
        const expectedAddress = (0, ethereumjs_util_1.toChecksumAddress)('0x' + expectedPublicKey.toString('hex'));
        const message = Buffer.concat([sender, addr, funcSig, ct]);
        const hash = (0, ethereumjs_util_1.keccak256)(message);
        // Recover the public key from the signature
        const publicKey = (0, ethereumjs_util_1.ecrecover)(hash, v, rBytes, sBytes);
        // Derive the Ethereum address from the recovered public key
        const address = (0, ethereumjs_util_1.toChecksumAddress)('0x' + publicKey.toString('hex'));
        // Compare the derived address with the expected signer's address
        const isVerified = address === expectedAddress;
        // Assert
        assert.strictEqual(isVerified, true);
    });
    // Test case for verify signature
    it('should sign and verify the EIP191 signature', () => {
        // Arrange
        // Simulate the generation of random bytes
        const sender = crypto_2.default.randomBytes(crypto_1.ADDRESS_SIZE);
        const addr = crypto_2.default.randomBytes(crypto_1.ADDRESS_SIZE);
        const funcSig = crypto_2.default.randomBytes(crypto_1.FUNC_SIG_SIZE);
        let key = (0, crypto_1.generateECDSAPrivateKey)();
        // Create a ciphertext
        const plaintextBuffer = Buffer.alloc(1);
        plaintextBuffer.writeUInt8(100);
        const aeskey = (0, crypto_1.generateAesKey)();
        const { ciphertext, r } = (0, crypto_1.encrypt)(aeskey, plaintextBuffer);
        let ct = Buffer.concat([ciphertext, r]);
        // Act
        // Generate the signature
        const signatureBytes = (0, crypto_1.signIT)(sender, addr, funcSig, ct, key, true);
        const { rBytes, sBytes, vByte } = extractSignatureComponents(signatureBytes);
        // Verify the signature
        const expectedPublicKey = (0, ethereumjs_util_1.privateToPublic)(key);
        const expectedAddress = (0, ethereumjs_util_1.toChecksumAddress)('0x' + expectedPublicKey.toString('hex'));
        const message = Buffer.concat([sender, addr, funcSig, ct]);
        const hash = (0, ethereumjs_util_1.hashPersonalMessage)(message);
        // Recover the public key from the signature
        const publicKey = (0, ethereumjs_util_1.ecrecover)(hash, vByte, rBytes, sBytes);
        // Derive the Ethereum address from the recovered public key
        const address = (0, ethereumjs_util_1.toChecksumAddress)('0x' + publicKey.toString('hex'));
        // Compare the derived address with the expected signer's address
        const isVerified = address === expectedAddress;
        // Assert
        assert.strictEqual(isVerified, true);
    });
    // Test case for verify signature
    it('should sign a fixed message and write the signature to a file', () => {
        // Arrange
        // Simulate the generation of random bytes
        const sender = Buffer.from('d67fe7792f18fbd663e29818334a050240887c28', 'hex');
        const addr = Buffer.from('69413851f025306dbe12c48ff2225016fc5bbe1b', 'hex');
        const funcSig = Buffer.from('dc85563d', 'hex');
        const ct = Buffer.from('f8765e191e03bf341c1422e0899d092674fc73beb624845199cd6e14b7895882', 'hex');
        const key = Buffer.from('3840f44be5805af188e9b42dda56eb99eefc88d7a6db751017ff16d0c5f8143e', 'hex');
        // Act
        // Generate the signature
        const signature = (0, crypto_1.signIT)(sender, addr, funcSig, ct, key);
        const filename = 'test_jsSignature.txt'; // Name of the file to write to
        // Convert hexadecimal string to buffer
        let sigString = signature.toString('hex');
        // Write buffer to the file, this simulates the communication between the evm (golang) and the user (python/js)
        fs_1.default.writeFile(filename, sigString, (err) => {
            if (err) {
                console.error('Error writing to file:', err);
                return;
            }
        });
    });
    it('should prepareMessage using fixed data', async () => {
        // Arrange
        // Simulate the generation of random bytes
        const plaintext = BigInt("100");
        const userKey = 'b3c3fe73c1bb91862b166a29fe1d63e9';
        const senderAddress = '0x8f01160c98e5cdfa625197849c85cf5fc1f76b1b';
        const contractAddress = '0x69413851f025306dbe12c48ff2225016fc5bbe1b';
        const funcSig = 'test(bytes)';
        const signingKey = '0x3840f44be5805af188e9b42dda56eb99eefc88d7a6db751017ff16d0c5f8143e';
        // Act
        // Generate the signature
        const functionSelector = (0, crypto_1.getFuncSig)(funcSig);
        const { message } = (0, crypto_1.prepareMessage)(plaintext, senderAddress, userKey, contractAddress, '0x' + functionSelector.toString('hex'));
        const wallet = new ethers_1.ethers.Wallet(signingKey);
        const signature = await wallet.signMessage(message);
        const recoveredAddress = ethers_1.ethers.verifyMessage(message, signature);
        assert.strictEqual(recoveredAddress.toLowerCase(), senderAddress.toLowerCase());
    });
    // Test case for verify signature
    it('should prepare IT using fixed data', () => {
        // Arrange
        // Simulate the generation of random bytes
        const plaintext = BigInt("100");
        const userKey = Buffer.from('b3c3fe73c1bb91862b166a29fe1d63e9', 'hex');
        ;
        const sender = new ethereumjs_util_1.Address((0, ethereumjs_util_1.toBuffer)(Buffer.from('d67fe7792f18fbd663e29818334a050240887c28', 'hex')));
        const contract = new ethereumjs_util_1.Address((0, ethereumjs_util_1.toBuffer)(Buffer.from('69413851f025306dbe12c48ff2225016fc5bbe1b', 'hex')));
        const funcSig = 'test(bytes)';
        const signingKey = Buffer.from('3840f44be5805af188e9b42dda56eb99eefc88d7a6db751017ff16d0c5f8143e', 'hex');
        // Act
        // Generate the signature
        const hash_func = (0, crypto_1.getFuncSig)(funcSig);
        const { ctInt, signature } = (0, crypto_1.prepareIT)(plaintext, userKey, sender.toBuffer(), contract.toBuffer(), hash_func, signingKey);
        const ctHex = ctInt.toString(crypto_1.HEX_BASE);
        // Create a Buffer to hold the bytes
        const ctBuffer = Buffer.from(ctHex, 'hex');
        // Write Buffer to file to later check in Go
        fs_1.default.writeFileSync("test_jsIT.txt", ctHex + "\n" + signature.toString('hex'));
        // Decrypt the ct and check the decrypted value is equal to the plaintext
        const decryptedBuffer = (0, crypto_1.decrypt)(userKey, ctBuffer.subarray(crypto_1.BLOCK_SIZE, ctBuffer.length), ctBuffer.subarray(0, crypto_1.BLOCK_SIZE));
        // Convert the plaintext to bytes
        const hexString = plaintext.toString(16);
        const plaintextBytes = Buffer.from(hexString, 'hex');
        // Assert
        const expectedBytes = decryptedBuffer.subarray(decryptedBuffer.length - plaintextBytes.length, decryptedBuffer.length);
        assert.deepStrictEqual(plaintextBytes.toString('hex'), Buffer.from(expectedBytes).toString('hex'));
        const intResult = uint8ArrayToBigInt(decryptedBuffer);
        assert.deepStrictEqual(plaintext, intResult);
    });
    // Test case for test rsa encryption scheme
    it('should encrypt and decrypt a message using RSA scheme', () => {
        // Arrange
        const plaintext = 'hello world';
        const plaintextBuffer = Buffer.from(plaintext);
        const { publicKey, privateKey } = (0, crypto_1.generateRSAKeyPair)();
        // Act
        const ciphertext = (0, crypto_1.encryptRSA)(publicKey, plaintext);
        const hexString = privateKey.toString('hex') + "\n" + publicKey.toString('hex');
        // Write buffer to the file
        const filename = 'test_jsRSAEncryption.txt'; // Name of the file to write to
        fs_1.default.writeFile(filename, hexString, (err) => {
            if (err) {
                console.error('Error writing to file:', err);
                return;
            }
        });
        const decrypted = (0, crypto_1.decryptRSA)(privateKey, Buffer.from(ciphertext).toString('hex'));
        // Assert
        assert.deepStrictEqual(plaintextBuffer, Buffer.from(decrypted));
    });
    function readHexFromFile(filename) {
        return new Promise((resolve, reject) => {
            fs_1.default.readFile(filename, 'utf8', (err, data) => {
                if (err) {
                    reject(err);
                    return;
                }
                const lines = data.trim().split('\n');
                if (lines.length >= 3) {
                    const hexData1 = lines[0].trim();
                    const hexData2 = lines[1].trim();
                    const hexData3 = lines[2].trim();
                    resolve([hexData1, hexData2, hexData3]);
                }
                else {
                    reject(new Error('Not enough lines in the file.'));
                }
            });
        });
    }
    // Test case for test rsa decryption scheme
    it('should decrypt a message using RSA scheme', () => {
        // Arrange
        const plaintext = Buffer.from('hello world');
        // Act
        // Read private key and ciphertext
        // Reading from file simulates the communication between the evm (golang) and the user (python/js)
        readHexFromFile('test_jsRSAEncryption.txt')
            .then((value) => {
            const [hexData1, hexData2, hexData3] = value;
            const privateKey = Buffer.from(hexData1, 'hex');
            const ciphertext = Buffer.from(hexData3, 'hex').toString('hex');
            const decrypted = (0, crypto_1.decryptRSA)(privateKey, hexData3);
            // Assert
            assert.deepStrictEqual(plaintext, decrypted);
        })
            .catch(error => {
            console.error("Error reading file:", error);
        });
        fs_1.default.unlinkSync('test_jsRSAEncryption.txt');
    });
    // Test case for test function signature
    it('should hash a function signature', () => {
        // Arrange
        const functionSig = 'sign(bytes)';
        // Act
        const hash = (0, crypto_1.getFuncSig)(functionSig);
        const filename = 'test_jsFunctionKeccak.txt'; // Name of the file to write to
        // Write Buffer to file
        fs_1.default.writeFileSync(filename, hash.toString('hex'));
    });
});
