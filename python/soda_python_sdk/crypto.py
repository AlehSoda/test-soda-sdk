from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import keccak
import os
import binascii
import struct
from eth_keys import keys
from Crypto.PublicKey import ECC
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from eth_account import Account
from eth_account.messages import encode_defunct

block_size = AES.block_size
address_size = 20
func_sig_size = 4
ct_size = 32
key_size = 32

def encrypt(key, plaintext):

    # Ensure plaintext is smaller than 128 bits (16 bytes)
    if len(plaintext) > block_size:
        raise ValueError("Plaintext size must be 128 bits or smaller.")

    # Ensure key size is 128 bits (16 bytes)
    if len(key) != block_size:
        raise ValueError("Key size must be 128 bits.")

    # Create a new AES cipher block using the provided key
    cipher = AES.new(key, AES.MODE_ECB)

    # Generate a random value 'r' of the same length as the block size
    r = get_random_bytes(block_size)

    # Encrypt the random value 'r' using AES in ECB mode
    encrypted_r = cipher.encrypt(r)

    # Pad the plaintext with zeros if it's smaller than the block size
    plaintext_padded = bytes(block_size - len(plaintext)) + plaintext

    # XOR the encrypted random value 'r' with the plaintext to obtain the ciphertext
    ciphertext = bytes(x ^ y for x, y in zip(encrypted_r, plaintext_padded))

    return ciphertext, r

def decrypt(key, r, ciphertext):

    if len(ciphertext) != block_size:
        raise ValueError("Ciphertext size must be 128 bits.")

    # Ensure key size is 128 bits (16 bytes)
    if len(key) != block_size:
        raise ValueError("Key size must be 128 bits.")

    # Ensure random size is 128 bits (16 bytes)
    if len(r) != block_size:
        raise ValueError("Random size must be 128 bits.")

    # Create a new AES cipher block using the provided key
    cipher = AES.new(key, AES.MODE_ECB)

    # Encrypt the random value 'r' using AES in ECB mode
    encrypted_r = cipher.encrypt(r)

    # XOR the encrypted random value 'r' with the ciphertext to obtain the plaintext
    plaintext = bytes(x ^ y for x, y in zip(encrypted_r, ciphertext))

    return plaintext

def load_aes_key(file_path):
    # Read the hex-encoded contents of the file
    with open(file_path, 'r') as file:
        hex_key = file.read().strip()

    # Decode the hex string to binary
    key = binascii.unhexlify(hex_key)

    # Ensure the key is the correct length
    if len(key) != block_size:
        raise ValueError(f"Invalid key length: {len(key)} bytes, must be {block_size} bytes")

    return key

def write_aes_key(file_path, key):
    # Ensure the key is the correct length
    if len(key) != block_size:
        raise ValueError(f"Invalid key length: {len(key)} bytes, must be {block_size} bytes")

    # Encode the key to hex string
    hex_key = binascii.hexlify(key).decode()

    # Write the hex-encoded key to the file
    with open(file_path, 'w') as file:
        file.write(hex_key)

def generate_aes_key():
    # Generate a random 128-bit AES key
    key = get_random_bytes(block_size)

    return key

def generate_ECDSA_private_key():

    # Generate a new ECDSA private key
    private_key = ECC.generate(curve='P-256')


    # Get the raw bytes of the private key
    return private_key.d.to_bytes(private_key.d.size_in_bytes(), byteorder='big')


def validate_input_lengths(sender, addr, func_sig, ct, key):
    """Validate the lengths of inputs."""
    if len(sender) != address_size:
        raise ValueError(f"Invalid sender address length: {len(sender)} bytes, must be {address_size} bytes")
    if len(addr) != address_size:
        raise ValueError(f"Invalid contract address length: {len(addr)} bytes, must be {address_size} bytes")
    if len(func_sig) != func_sig_size:
        raise ValueError(f"Invalid signature size: {len(func_sig)} bytes, must be {func_sig_size} bytes")
    if len(ct) != ct_size:
        raise ValueError(f"Invalid ct length: {len(ct)} bytes, must be {ct_size} bytes")
    if len(key) != key_size:
        raise ValueError(f"Invalid key length: {len(key)} bytes, must be {key_size} bytes")


def signIT(sender, addr, func_sig, ct, key, eip191=False):
    """Sign the message using either standard signing or EIP-191 signing."""
    # Validate input lengths
    validate_input_lengths(sender, addr, func_sig, ct, key)

    # Create the message to be signed by appending all inputs
    message = sender + addr + func_sig + ct

    # Sign the message
    if eip191:
        return sign_eip191(message, key)
    else:
        return sign(message, key)


def sign(message, key):
    # Sign the message
    pk = keys.PrivateKey(key)
    signature = pk.sign_msg(message).to_bytes()
    return signature


def sign_eip191(message, key):
    signed_message = Account.sign_message(encode_defunct(primitive=message), key)
    return signed_message.signature


def prepare_IT(plaintext, user_aes_key, sender, contract, func_sig, signing_key, eip191=False):
    # Create the function signature
    func_hash = get_func_sig(func_sig)

    return inner_prepare_IT(plaintext, user_aes_key, sender, contract, func_hash, signing_key, eip191)

def inner_prepare_IT(plaintext, user_aes_key, sender, contract, func_sig_hash, signing_key, eip191):
    # Get addresses as bytes
    sender_address_bytes = bytes.fromhex(sender.address[2:])
    contract_address_bytes = bytes.fromhex(contract.address[2:])

    # Convert the integer to a byte slice with size aligned to 8.
    plaintext_bytes = plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big')

    # Encrypt the plaintext with the user's AES key
    ciphertext, r = encrypt(user_aes_key, plaintext_bytes)
    ct = ciphertext + r

    # Sign the message
    signature = signIT(sender_address_bytes, contract_address_bytes, func_sig_hash, ct, signing_key, eip191)

    # Convert the ct to an integer
    ctInt = int.from_bytes(ct, byteorder='big')

    return ctInt, signature


def generate_rsa_keypair():
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Serialize private key
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Get public key
    public_key = private_key.public_key()
    # Serialize public key
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_bytes, public_key_bytes

def encrypt_rsa(public_key_bytes, plaintext):
    # Load public key
    public_key = serialization.load_der_public_key(public_key_bytes)
    # Encrypt plaintext
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_rsa(private_key_bytes, ciphertext):
    # Load private key
    private_key = serialization.load_der_private_key(private_key_bytes, password=None)
    # Decrypt ciphertext
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def recover_user_key(private_key_bytes, encrypted_key_share0, encrypted_key_share1):
    """
    This function recovers a user's key by decrypting two encrypted key shares with the given private key,
    and then XORing the two key shares together.

    Args:
        private_key_bytes (bytes): The private key used to decrypt the key shares.
        encrypted_key_share0 (bytes): The first encrypted key share.
        encrypted_key_share1 (bytes): The second encrypted key share.

    Returns:
        bytes: The recovered user key.
    """
    key_share0 = decrypt_rsa(private_key_bytes, encrypted_key_share0)
    key_share1 = decrypt_rsa(private_key_bytes, encrypted_key_share1)

    # XOR both key shares to get the user key
    return bytes([a ^ b for a, b in zip(key_share0, key_share1)])

# Function to compute Keccak-256 hash
def keccak256(data):
    # Create Keccak-256 hash object
    hash_obj = keccak.new(digest_bits=256)

    # Update hash object with data
    hash_obj.update(data)

    # Compute hash and return
    return hash_obj.digest()


def get_func_sig(functionSig):
    # Convert function signature to bytes
    functionSigBytes = functionSig.encode('utf-8')

    # Compute Keccak-256 hash on the function signature
    hash = keccak256(functionSigBytes)

    # Take first 4 bytes of the hash 
    return hash[:4]



