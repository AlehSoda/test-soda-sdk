import {BLOCK_SIZE} from "./crypto.js";
import {ethers} from "ethers";
import fs from "fs";

export function loadAesKey(filePath) {

    // Read the hex-encoded contents of the file
    const hexKey = fs.readFileSync(filePath, 'utf8').trim();

    // Decode the hex string to binary
    const key = Buffer.from(hexKey.slice(2), 'hex');

    // Ensure the key is the correct length
    if (key.length !== BLOCK_SIZE) {
        throw new RangeError(`Invalid key length: ${key.length} bytes, must be 16 bytes`);
    }

    return key;
}

export function writeAesKey(filePath, key) {

    // Ensure the key is the correct length
    if (key.length !== BLOCK_SIZE) {
        throw new RangeError(`Invalid key length: ${key.length} bytes, must be 16 bytes`);
    }

    // Encode the key to hex string
    const hexKey = ethers.hexlify(key);

    // Write the hex-encoded key to the file
    fs.writeFileSync(filePath, hexKey, 'utf8');
}