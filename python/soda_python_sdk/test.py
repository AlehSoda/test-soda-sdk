import unittest
import tempfile
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from crypto import encrypt, decrypt, load_aes_key, write_aes_key, generate_aes_key, signIT, generate_rsa_keypair, encrypt_rsa, decrypt_rsa, get_func_sig, prepare_IT, generate_ECDSA_private_key
from crypto import block_size, address_size, func_sig_size, key_size
from eth_keys import keys
from web3 import Account
from eth_account.messages import encode_defunct

class TestMpcHelper(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for key files
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        # Clean up the temporary directory
        self.temp_dir.cleanup()

    def test_encrypt_decrypt(self):
        # Arrange
        # Generate a key
        key = generate_aes_key()

        # Provide plaintext integer
        plaintext_integer = 100
        
        # Convert the integer to a byte slice with size aligned to 8.
        plaintext_message = plaintext_integer.to_bytes((plaintext_integer.bit_length() + 7) // 8, 'big')

        # Act
        # Call the encrypt function
        ciphertext, r = encrypt(key, plaintext_message)

        # Writing to a file to later check in Go
        with open("test_pythonEncryption.txt", "w") as f:
            f.write(key.hex())
            f.write("\n")
            f.write(ciphertext.hex())
            f.write("\n")
            f.write(r.hex())

        # Call the decrypt function
        decrypted_message = decrypt(key, r, ciphertext)

        decrypted_integer = int.from_bytes(decrypted_message, 'big')

        # Assert
        # Ensure the decrypted message is equal to the original plaintext
        self.assertEqual(plaintext_integer, decrypted_integer)

    def test_load_write_aes_key(self):
        # Arrange
        # Generate a key
        key = generate_aes_key()
        
        # Act
        # Create the file path for the key
        key_file_path = os.path.join(self.temp_dir.name, "key.txt")
        write_aes_key(key_file_path, key)

        # Load the key from the file
        loaded_key = load_aes_key(key_file_path)

        # Assert
        # Ensure the loaded key is equal to the original key
        self.assertEqual(loaded_key, key)

        # Remove the key file
        os.remove(key_file_path)

    def test_invalid_plaintext_size(self):
        # Arrange
        # Generate a key
        key = generate_aes_key()

        # Invalid plaintext size (more than block_size)
        invalid_plaintext = bytes(block_size + 1)

        # Act and Assert
        # Expect an error to be thrown when decrypting
        with self.assertRaises(ValueError):
            encrypt(key, invalid_plaintext)

    def test_invalid_ciphertext_size(self):
        # Arrange
        # Generate a key
        key = generate_aes_key()

        # Invalid ciphertext size (less than block_size)
        invalid_ciphertext = b'\x01\x02\x03'

        # Act and Assert
        # Expect an error to be thrown when decrypting
        with self.assertRaises(ValueError):
            decrypt(key, get_random_bytes(block_size), invalid_ciphertext)

    def test_invalid_random_size(self):
        # Arrange
        # Generate a key
        key = generate_aes_key()

        # Invalid ciphertext size (less than block_size)
        invalid_random = b'\x01\x02\x03'

        # Act and Assert
        # Expect an error to be thrown when decrypting
        with self.assertRaises(ValueError):
            decrypt(key, invalid_random, get_random_bytes(block_size))

    def test_invalid_key_length(self):
        # Arrange
        # Invalid key length (less than block_size)
        invalid_key = get_random_bytes(3)

        # Act and Assert
        # Expect an error to be thrown when writing the key
        with self.assertRaises(ValueError):
            write_aes_key(os.path.join(self.temp_dir.name, "/invalid_key.txt"), invalid_key)

        # Expect an error to be thrown when writing the key
        with self.assertRaises(ValueError):
            encrypt(invalid_key, get_random_bytes(3))
        
        # Expect an error to be thrown when writing the key
        with self.assertRaises(ValueError):
            decrypt(invalid_key, get_random_bytes(3), get_random_bytes(3))

    def test_signature(self):
        # Arrange
        sender = os.urandom(address_size)
        addr = os.urandom(address_size)
        func_sig = os.urandom(func_sig_size)
        key = generate_ECDSA_private_key()

        # Create plaintext with the value 100 as a big integer with less than 128 bits
        plaintext_integer = 100
        # Convert the integer to a byte slice with size aligned to 8.
        plaintext_message = plaintext_integer.to_bytes((plaintext_integer.bit_length() + 7) // 8, 'little')
        # Call the encrypt function
        ciphertext, r = encrypt(generate_aes_key(), plaintext_message)
        ct = ciphertext + r

        # Act
        # Call the sign function
        signature_bytes = signIT(sender, addr, func_sig, ct, key)
        
        # Create the message to be 
        message = sender + addr + func_sig + ct

        pk = keys.PrivateKey(key)
        signature = keys.Signature(signature_bytes)
        # Verify the signature against the message hash and the public key
        verified = signature.verify_msg(message, pk.public_key)
       
        # Assert
        self.assertEqual(verified, True)

    def test_signature_eip191(self):
        # Arrange
        sender = os.urandom(address_size)
        addr = os.urandom(address_size)
        func_sig = os.urandom(func_sig_size)
        key = generate_ECDSA_private_key()

        # Create plaintext with the value 100 as a big integer with less than 128 bits
        plaintext_integer = 100
        # Convert the integer to a byte slice with size aligned to 8.
        plaintext_message = plaintext_integer.to_bytes((plaintext_integer.bit_length() + 7) // 8, 'little')
        # Call the encrypt function
        ciphertext, r = encrypt(generate_aes_key(), plaintext_message)
        ct = ciphertext + r

        # Act
        # Call the sign function
        signature_bytes = signIT(sender, addr, func_sig, ct, key, eip191=True)

        # Create the message to be
        message = sender + addr + func_sig + ct
        encoded_message = encode_defunct(primitive=message)
        recovered_address = Account.recover_message(encoded_message, signature=signature_bytes)

        account_address = Account.from_key(key).address

        # Assert
        self.assertEqual(recovered_address, account_address)

    def test_fixedMSG_Signature(self):
        # Arrange
        sender = bytes.fromhex("d67fe7792f18fbd663e29818334a050240887c28")
        addr = bytes.fromhex("69413851f025306dbe12c48ff2225016fc5bbe1b")
        func_sig = bytes.fromhex("dc85563d")
        ct = bytes.fromhex("f8765e191e03bf341c1422e0899d092674fc73beb624845199cd6e14b7895882")
        key = bytes.fromhex("3840f44be5805af188e9b42dda56eb99eefc88d7a6db751017ff16d0c5f8143e")

        # Act
        # Call the sign function
        signature_bytes = signIT(sender, addr, func_sig, ct, key)
        # Write hexadecimal string to a file, this simulates the communication between the evm (golang) and the user (python/js)
        with open("test_pythonSignature.txt", "w") as f:
            f.write(signature_bytes.hex())
        
        # Create the message to be 
        message = sender + addr + func_sig + ct

        pk = keys.PrivateKey(key)
        signature = keys.Signature(signature_bytes)
        # Verify the signature against the message hash and the public key
        verified = signature.verify_msg(message, pk.public_key)
       
        # Assert
        self.assertEqual(verified, True)
    
    def test_prepareIT(self):
        # Arrange
        plaintext = 100
        userKey = bytes.fromhex("b3c3fe73c1bb91862b166a29fe1d63e9")
        # Create an account object manually
        sender = Account()
        sender.address = "0xd67fe7792f18fbd663e29818334a050240887c28"
        contract = Account()
        contract.address = "0x69413851f025306dbe12c48ff2225016fc5bbe1b"
        func_sig = "test(bytes)"
        signingKey = bytes.fromhex("3840f44be5805af188e9b42dda56eb99eefc88d7a6db751017ff16d0c5f8143e")

        # Act
        # Call the sign function
        ct, signature = prepare_IT(plaintext, userKey, sender, contract, func_sig, signingKey)
        # Write hexadecimal string to a file, this simulates the communication between the evm (golang) and the user (python/js)
        with open("test_pythonIT.txt", "w") as f:
            f.write(ct.to_bytes((ct.bit_length() + 7) // 8, 'big').hex())
            f.write("\n")
            f.write(signature.hex())

        sender_address_bytes = bytes.fromhex(sender.address[2:])
        contract_address_bytes = bytes.fromhex(contract.address[2:])

        # create the function signature
        func_hash = get_func_sig(func_sig)

        # Convert the integer to a byte slice with size aligned to 8.
        ctBytes = ct.to_bytes((ct.bit_length() + 7) // 8, 'big')

         # Create the message to be signed
        message = sender_address_bytes + contract_address_bytes + func_hash + ctBytes

        pk = keys.PrivateKey(signingKey)
        signature = keys.Signature(signature)
        # Verify the signature against the message hash and the public key
        verified = signature.verify_msg(message, pk.public_key)
       
        # Assert
        self.assertEqual(verified, True)

        decrypted = decrypt(userKey, ctBytes[block_size:], ctBytes[:block_size])
        decrypted_integer = int.from_bytes(decrypted, 'big')
        self.assertEqual(plaintext, decrypted_integer)

    def test_rsa_encryption(self):
        # Arrange
        plaintext = b"hello world"
        private_key, public_key = generate_rsa_keypair()

        # Act
        ciphertext = encrypt_rsa(public_key, plaintext)

        # Writing to a file simulates the communication between the evm (golang) and the user (python/js)
        with open("test_pythonRSAEncryption.txt", "w") as f:
            f.write(private_key.hex())
            f.write("\n")
            f.write(public_key.hex())

        decrypted = decrypt_rsa(private_key, ciphertext)

        # Assert
        self.assertEqual(plaintext, decrypted)

    def test_get_func_sig(self):
        # Arrange
        functionSig = "sign(bytes)"
        # Act
        hashed = get_func_sig(functionSig)

        # Writing to a file simulates the communication between the evm (golang) and the user (python/js)
        with open("test_pythonFunctionKeccak.txt", "w") as f:
            f.write(hashed.hex())

class TestDecrypt(unittest.TestCase):

    def test_rsa_decryption(self):
        # Arrange
        plaintext = b"hello world"
        private_key_hex = ""
        public_key_hex = ""
        cipher_hex = ""

        # Reading from file simulates the communication between the evm (golang) and the user (python/js)
        with open("test_pythonRSAEncryption.txt", "r") as file:
            private_key_hex = file.readline().strip()  
            public_key_hex = file.readline().strip()  
            cipher_hex = file.readline().strip()  

        private_key = bytes.fromhex(private_key_hex)  
        public_key = bytes.fromhex(public_key_hex)  
        ciphertext = bytes.fromhex(cipher_hex)  
        
        # Act
        decrypted = decrypt_rsa(private_key, ciphertext)

        # Assert
        self.assertEqual(plaintext, decrypted)

        os.remove("test_pythonRSAEncryption.txt")


if __name__ == '__main__':
    unittest.main()