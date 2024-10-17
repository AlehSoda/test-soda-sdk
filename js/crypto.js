import forge from 'node-forge'
import {ethers} from "ethers";



export const BLOCK_SIZE = 16; // AES block size in bytes
export const ADDRESS_SIZE = 20; // 160-bit is the output of the Keccak-256 algorithm on the sender/contract address
export const FUNC_SIG_SIZE = 4;
export const CT_SIZE = 32;
export const KEY_SIZE = 32;
export const HEX_BASE = 16;

export function encrypt(key, plaintext) {
    
    // Ensure plaintext is smaller than 128 bits (16 bytes)
    if (plaintext.length > BLOCK_SIZE) {
        throw new RangeError("Plaintext size must be 128 bits or smaller.");
    }

    // Ensure key size is 128 bits (16 bytes)
    if (key.length !== BLOCK_SIZE) {
        throw new RangeError("Key size must be 128 bits.");
    }

    // Generate a random value 'r' of the same length as the block size
    const r = forge.random.getBytesSync(BLOCK_SIZE)

    // Encrypt the random value 'r' using AES in ECB mode
    const encryptedR = encryptNumber(r, key)
    
    // Pad the plaintext with zeros if it's smaller than the block size
    const plaintext_padded = Buffer.concat([Buffer.alloc(BLOCK_SIZE - plaintext.length), plaintext]);

    // XOR the encrypted random value 'r' with the plaintext to obtain the ciphertext
    const ciphertext = Buffer.alloc(encryptedR.length);
    for (let i = 0; i < encryptedR.length; i++) {
        ciphertext[i] = encryptedR[i] ^ plaintext_padded[i];
    }

    const uint8ArrayR = new Uint8Array(r.split('').map(c => c.charCodeAt(0)));

    return { ciphertext, r: Buffer.from(uint8ArrayR) };
}

export function decrypt(key, r, ciphertext) {

    if (ciphertext.length !== BLOCK_SIZE) {
        throw new RangeError("Ciphertext size must be 128 bits.");
    }

    // Ensure key size is 128 bits (16 bytes)
    if (key.length !== BLOCK_SIZE) {
        throw new RangeError("Key size must be 128 bits.");
    }

    // Ensure random size is 128 bits (16 bytes)
    if (r.length !== BLOCK_SIZE) {
        throw new RangeError("Random size must be 128 bits.");
    }

   // Get the encrypted random value 'r'
    const encryptedR = encryptNumber(r, key)

    // XOR the encrypted random value 'r' with the ciphertext to obtain the plaintext
    const plaintext = new Uint8Array(BLOCK_SIZE)

    for (let i = 0; i < encryptedR.length; i++) {
        plaintext[i] = encryptedR[i] ^ ciphertext[i]
    }

    return plaintext
}

export function generateAesKey() {
    // Generate a random 128-bit AES key
    const key = forge.random.getBytesSync(BLOCK_SIZE)

    // Convert the string of bytes to a Uint8Array
    const uint8ArrayKey = new Uint8Array(key.split('').map(c => c.charCodeAt(0)));

    return Buffer.from(uint8ArrayKey);
}

export function generateECDSAPrivateKey() {
    // Generate a random wallet (this includes an ECDSA private key using secp256k1)
    const wallet = ethers.Wallet.createRandom();

    // Get the private key as a 32-byte hexadecimal string (0x-prefixed)
    const privateKeyHex = wallet.privateKey;

    // Convert the private key hex string to a Buffer for a similar return type
    // Remove the "0x" prefix
    return Buffer.from(privateKeyHex.slice(2), 'hex');
}

export function signIT(sender, addr, funcSig, ct, key, eip191=false) {
    // Ensure all input sizes are the correct length
    if (sender.length !== ADDRESS_SIZE) {
        throw new RangeError(`Invalid sender address length: ${sender.length} bytes, must be ${ADDRESS_SIZE} bytes`);
    }
    if (addr.length !== ADDRESS_SIZE) {
        throw new RangeError(`Invalid contract address length: ${addr.length} bytes, must be ${ADDRESS_SIZE} bytes`);
    }
    if (funcSig.length !== FUNC_SIG_SIZE) {
        throw new RangeError(`Invalid signature size: ${funcSig.length} bytes, must be ${FUNC_SIG_SIZE} bytes`);
    }
    if (ct.length !== CT_SIZE) {
        throw new RangeError(`Invalid ct length: ${ct.length} bytes, must be ${CT_SIZE} bytes`);
    }
    // Ensure the key is the correct length
    if (key.length !== KEY_SIZE) {
        throw new RangeError(`Invalid key length: ${key.length} bytes, must be ${KEY_SIZE} bytes`);
    }

    // Create the message to be signed by concatenating all inputs
    let message = Buffer.concat([sender, addr, funcSig, ct]);

    // Concatenate r, s, and v bytes
    if (eip191) {
        return signEIP191(message, key);
    }else {
        return sign(message, key);
    }
}

export function sign(message, key) {

    // Hash the concatenated message using Keccak-256
    const hash = ethers.keccak256(message);

    // Sign the message
    const signingKey = new ethers.SigningKey(key);
    const signature = signingKey.sign(hash);

    // Concatenate r, s, and v bytes
    return Buffer.concat([ethers.getBytes(signature.r), ethers.getBytes(signature.s), ethers.getBytes(`0x0${signature.v - 27}`)]);
}

export function signEIP191(message, key) {
    // Hash the concatenated message using Keccak-256
    const hash = ethers.hashMessage(message);
    // Sign the message
    const signingKey = new ethers.SigningKey(key);
    const signature = signingKey.sign(hash);
    // Convert r, s, and v components to bytes
    return Buffer.concat([ethers.getBytes(signature.r), ethers.getBytes(signature.s), ethers.getBytes(`0x0${signature.v - 27}`)]);
}

export function prepareMessage(plaintext, signerAddress, aesKey, contractAddress, functionSelector) {
  // Validate signerAddress (Ethereum address)
  if (!ethers.isAddress(signerAddress)) {
    throw new TypeError("Invalid signer address");
  }

  // Validate aesKey (32 bytes as hex string)
  if (typeof aesKey !== "string" || aesKey.length != 32) {
    throw new TypeError("Invalid AES key length. Expected 32 bytes.");
  }

  // Validate contractAddress (Ethereum address)
  if (typeof contractAddress !== "string" || !ethers.isAddress(signerAddress)) {
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
  const {ciphertext, r} = encryptAES(plaintextBytes.toString("hex"), aesKey);
  const ct = Buffer.concat([ciphertext, r]);

  const message = ethers.solidityPacked(
    ["address", "address", "bytes4", "uint256"],
    [signerAddress, contractAddress, functionSelector, BigInt("0x" + ct.toString("hex"))],
  );
  // Convert the ciphertext to BigInt
  const encryptedInt = BigInt("0x" + ct.toString("hex"));

  return {encryptedInt, messageHash: message}
}

export function prepareIT(plaintext, userAesKey, sender, contract, hashFunc, signingKey, eip191=false) {

    // Get the bytes of the sender, contract, and function signature
    const senderBytes = Buffer.from(sender.toBuffer())
    const contractBytes = Buffer.from(contract.toBuffer())

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

export function generateRSAKeyPair(){
    // Generate a new RSA key pair
    const rsaKeyPair = forge.pki.rsa.generateKeyPair({bits: 2048})

    // Convert keys to DER format
    const privateKey = forge.asn1.toDer(forge.pki.privateKeyToAsn1(rsaKeyPair.privateKey)).data
    const publicKey = forge.asn1.toDer(forge.pki.publicKeyToAsn1(rsaKeyPair.publicKey)).data

    return {
        privateKey: Buffer.from(encodeString(privateKey)),
        publicKey: Buffer.from(encodeString(publicKey))
    }
}

export function encryptRSA(publicKeyUint8Array, plaintext) {
    // Convert the Uint8Array to a binary string for forge
    const binaryDerString = String.fromCharCode.apply(null, publicKeyUint8Array);

    // Decode the binary DER string into an ASN.1 object
    const asn1PublicKey = forge.asn1.fromDer(binaryDerString);

    // Convert the ASN.1 object to an RSA public key
    const forgePublicKey = forge.pki.publicKeyFromAsn1(asn1PublicKey);

    // Encrypt the plaintext using RSA-OAEP with SHA-256 as the hash function
    const encrypted = forgePublicKey.encrypt(plaintext, 'RSA-OAEP', {
        md: forge.md.sha256.create()  // Use SHA-256 for OAEP padding
    });

    // Convert the encrypted binary string to a Uint8Array
    return new Uint8Array(forge.util.createBuffer(encrypted, 'raw').bytes().split('').map(c => c.charCodeAt(0)));
}

export function decryptRSA(privateKeyUint8Array, ciphertext) {
    // Convert privateKey from Uint8Array to PEM format
    const privateKeyPEM = forge.pki.privateKeyToPem(
        forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(forge.util.createBuffer(privateKeyUint8Array)))
    );

    // Decrypt using RSA-OAEP
    const rsaPrivateKey = forge.pki.privateKeyFromPem(privateKeyPEM);

    // If ciphertext is Uint8Array, convert it to a binary string for forge
    let binaryCiphertext;
    if (ciphertext instanceof Uint8Array) {
        binaryCiphertext = String.fromCharCode.apply(null, ciphertext);
    } else if (typeof ciphertext === 'string') {
        // If it's already a hex string, convert hex to bytes
        binaryCiphertext = forge.util.hexToBytes(ciphertext);
    } else {
        throw new Error("Invalid ciphertext format");
    }

    // Decrypt the ciphertext using RSA-OAEP with SHA-256
    const decrypted = rsaPrivateKey.decrypt(binaryCiphertext, 'RSA-OAEP', {
        md: forge.md.sha256.create()
    });

    // Convert the decrypted string to a Uint8Array
    return new Uint8Array(decrypted.split('').map(c => c.charCodeAt(0)));
}

export function getFuncSig(functionSig) {
    const functionSelector = ethers.id(functionSig).slice(0, 10);
    return Buffer.from(functionSelector.slice(2, 10), 'hex')
}


export function encodeString(str) {
    return new Uint8Array([...str.split('').map((char) => parseInt(char.codePointAt(0)?.toString(HEX_BASE), HEX_BASE))])
}


export function encryptNumber(r, key) {
    // Ensure key size is 128 bits (16 bytes)
    if (key.length !== BLOCK_SIZE) {
        throw new RangeError("Key size must be 128 bits.")
    }

    // Create a new AES cipher using the provided key
    const cipher = forge.cipher.createCipher('AES-ECB', forge.util.createBuffer(key))

    // Encrypt the random value 'r' using AES in ECB mode
    cipher.start()
    cipher.update(forge.util.createBuffer(r))
    cipher.finish()

    // Get the encrypted random value 'r' as a Buffer and ensure it's exactly 16 bytes
    return encodeString(cipher.output.data).slice(0, BLOCK_SIZE)
}

