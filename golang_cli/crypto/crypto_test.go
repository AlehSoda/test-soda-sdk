// crypto_test.go
package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func encryptDecrypt(t *testing.T, plaintextBytes []byte) []byte {
	key := make([]byte, aes.BlockSize)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	ciphertext, r, err := Encrypt(key, plaintextBytes)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(key, r, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	return decrypted
}

func TestEncryptDecrypt(t *testing.T) {
	// Arrange
	// Create plaintext with the value 100 as a big integer with 128 bits
	plaintextValue := big.NewInt(100)
	plaintextBytes := make([]byte, aes.BlockSize)
	plaintextValue.FillBytes(plaintextBytes)

	// Act
	decrypted := encryptDecrypt(t, plaintextBytes)

	// Assert
	assert.Equal(t, plaintextBytes, decrypted, "Decrypted message should match the original plaintext")
}

func TestEncryptDecryptWithPadding(t *testing.T) {
	// Arrange
	// Create plaintext with the value 100 as a big integer with less than 128 bits
	plaintextValue := big.NewInt(100)
	plaintextBytes := plaintextValue.Bytes()

	// Act
	decrypted := encryptDecrypt(t, plaintextBytes)
	decryptedValue := new(big.Int).SetBytes(decrypted)

	// Assert
	assert.Equal(t, plaintextValue, decryptedValue, "Decrypted message should match the original plaintext")
}

func readEncryptionFromFile(path string) ([]byte, []byte, []byte, error) {
	data, err := readValFromFile(path)
	if err != nil {
		return nil, nil, nil, err
	}

	// Split the data into two hex strings
	hexStrings := bytes.Split(data, []byte("\n"))

	// Convert the hex strings to bytes
	if len(hexStrings) != 3 {
		return nil, nil, nil, fmt.Errorf("Expected three hex strings in the file")
	}

	keyBytes, err := hex.DecodeString(string(hexStrings[0]))
	if err != nil {
		fmt.Println("Error decoding hex:", err)
		return nil, nil, nil, err
	}

	cipherBytes, err := hex.DecodeString(string(hexStrings[1]))
	if err != nil {
		fmt.Println("Error decoding hex:", err)
		return nil, nil, nil, err
	}

	randomBytes, err := hex.DecodeString(string(hexStrings[2]))
	if err != nil {
		fmt.Println("Error decoding hex:", err)
		return nil, nil, nil, err
	}

	return keyBytes, cipherBytes, randomBytes, nil
}

func checkEncryption(t *testing.T, filePath string) {
	// Arrange
	plaintextValue := big.NewInt(100)

	// Read encryption from a file
	key, ciphertext, r, err := readEncryptionFromFile(filePath)
	require.NoError(t, err, "Read encryption should not return an error")

	err = os.Remove(filePath)
	require.NoError(t, err, "Delete file should not return an error")

	// Act
	decrypted, err := Decrypt(key, r, ciphertext)
	require.NoError(t, err, "Decrypt should not return an error")

	decryptedValue := new(big.Int).SetBytes(decrypted)

	// Assert
	assert.Equal(t, plaintextValue, decryptedValue, "Python decrypted message should match the original plaintext")
}

func TestPythonJSEnsryption(t *testing.T) {

	checkEncryption(t, "../../python/soda_python_sdk/test_pythonEncryption.txt")
	checkEncryption(t, "../../js/test_jsEncryption.txt")
}

func TestLoadWriteAESKey(t *testing.T) {
	// Arrange and Assert
	// Create a temporary file for testing
	tempFile := "temp_key_file.txt"
	defer os.Remove(tempFile)

	key := make([]byte, aes.BlockSize)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	// Act and Assert
	// Test WriteAESKey
	err = WriteAESKey(tempFile, key)
	require.NoError(t, err, "WriteAESKey should not return an error")

	// Test LoadAESKey
	loadedKey, err := LoadAESKey(tempFile)
	require.NoError(t, err, "LoadAESKey should not return an error")
	assert.Equal(t, key, loadedKey, "Loaded key should match the original key")
}

func TestGenerateAndWriteAESKey(t *testing.T) {
	// Arrange and Assert
	// Create a temporary file for testing
	tempFile := "temp_key_file.txt"
	defer os.Remove(tempFile)
	// Test GenerateAESKey and WriteAESKey
	key, err := GenerateAESKey()
	require.NoError(t, err, "GenerateAESKey should not return an error")

	// Act and Assert
	err = WriteAESKey(tempFile, key)
	require.NoError(t, err, "WriteAESKey should not return an error")

	// Verify that the key was written to the file
	loadedKey, err := LoadAESKey(tempFile)
	require.NoError(t, err, "LoadAESKey should not return an error")
	assert.Equal(t, key, loadedKey, "Loaded key should match the generated key")
}

func TestSignature(t *testing.T) {
	// Arrange
	sender := make([]byte, AddressSize)
	_, err := rand.Read(sender)
	addr := make([]byte, AddressSize)
	_, err = rand.Read(addr)
	funcSig := make([]byte, FuncSigSize)
	_, err = rand.Read(funcSig)

	key := GenerateECDSAPrivateKey()
	require.NoError(t, err, "Failed to generate random key")

	// Create plaintext with the value 100 as a big integer with less than 128 bits
	plaintextValue := big.NewInt(100)
	plaintextBytes := plaintextValue.Bytes()
	ciphertext, r, err := Encrypt(key, plaintextBytes)
	require.NoError(t, err, "Encrypt should not return an error")

	ct := append(ciphertext, r...)

	// Act and assert
	signature, err := SignIT(sender, addr, funcSig, ct, key)
	require.NoError(t, err, "Sign should not return an error")

	// Verify the signature
	verified := VerifyIT(sender, addr, funcSig, ct, signature)

	assert.Equal(t, verified, true, "Verify signature should return true")
}

func readValFromFile(path string) ([]byte, error) {
	// Open the file for reading
	file, err := os.Open(path)
	if err != nil {
		fmt.Println("Error:", err)
		return nil, err
	}
	defer file.Close() // Make sure to close the file when done

	// Read the contents of the file as a string
	data, err := io.ReadAll(file)
	if err != nil {
		fmt.Println("Error:", err)
		return nil, err
	}

	return data, nil
}

func readHexValFromFile(path string) ([]byte, error) {
	data, err := readValFromFile(path)
	if err != nil {
		return nil, err
	}

	// Convert the hex string to bytes
	hexBytes, err := hex.DecodeString(string(data))
	if err != nil {
		fmt.Println("Error decoding hex:", err)
		return nil, err
	}

	return hexBytes, nil
}

func readSigFromFileAndCompare(t *testing.T, filePath string, signature []byte) {
	fileSig, err := readHexValFromFile(filePath)
	require.NoError(t, err, "Read Signature should not return an error")

	err = os.Remove(filePath)
	require.NoError(t, err, "Delete file should not return an error")

	assert.Equal(t, fileSig, signature, "signature should match the python signature")
}

// TestFixedMsgSignature is a test function that checks the functionality of the Sign and VerifySignature functions.
// It first decodes fixed hexadecimal strings into byte slices representing the sender, address, function signature, ciphertext, and key.
// It then signs a message using these parameters and checks for errors.
// The function then reads signatures from two files (one Python and one JavaScript) and compares them to the generated signature.
// This ensures that the signature is correct in both python and javascript implementations.
// It then verifies the signature using the VerifySignature function and asserts that the result should be true.
func TestFixedMsgSignature(t *testing.T) {
	// Arrange
	// Create plaintext with the value 100 as a big integer with less than 128 bits
	sender, _ := hex.DecodeString("d67fe7792f18fbd663e29818334a050240887c28")
	addr, _ := hex.DecodeString("69413851f025306dbe12c48ff2225016fc5bbe1b")
	funcSig, _ := hex.DecodeString("dc85563d")
	ct, _ := hex.DecodeString("f8765e191e03bf341c1422e0899d092674fc73beb624845199cd6e14b7895882")
	key, _ := hex.DecodeString("3840f44be5805af188e9b42dda56eb99eefc88d7a6db751017ff16d0c5f8143e")

	// Act and assert
	// Sign the message
	signature, err := SignIT(sender, addr, funcSig, ct, key)
	require.NoError(t, err, "Sign should not return an error")

	// Reading from file simulates the communication between the evm (golang) and the user (python/js)
	readSigFromFileAndCompare(t, "../../python/soda_python_sdk/test_pythonSignature.txt", signature)
	readSigFromFileAndCompare(t, "../../js/test_jsSignature.txt", signature)

	// Verify the signature
	verified := VerifyIT(sender, addr, funcSig, ct, signature)

	assert.Equal(t, verified, true, "Verify signature should return true")
}

func TestIT(t *testing.T) {
	// Arrange
	// Create plaintext with the value 100 as a big integer with less than 128 bits
	plaintext := uint64(100)
	sender := common.HexToAddress("d67fe7792f18fbd663e29818334a050240887c28")
	contract := common.HexToAddress("69413851f025306dbe12c48ff2225016fc5bbe1b")
	funcSig := "test(bytes)"
	userKey, _ := hex.DecodeString("b3c3fe73c1bb91862b166a29fe1d63e9")
	signingKey, _ := hex.DecodeString("3840f44be5805af188e9b42dda56eb99eefc88d7a6db751017ff16d0c5f8143e")

	// Act and assert
	// Sign the message
	ct, signature, err := prepareIT(plaintext, userKey, sender, contract, funcSig, signingKey)
	require.NoError(t, err, "Sign should not return an error")

	plaintextBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(plaintextBytes, plaintext)

	checkIT(t, plaintextBytes, userKey, sender.Bytes(), contract.Bytes(), GetFuncSig(funcSig), ct.Bytes(), signature)

	// Reading from file simulates the communication between the evm (golang) and the user (python/js)
	pythonCt, pythonSignature, err := readTwoHexStringsFromFile("../../python/soda_python_sdk/test_pythonIT.txt")
	require.NoError(t, err, "Read file should not return an error")
	checkIT(t, plaintextBytes, userKey, contract.Bytes(), GetFuncSig(funcSig), ct.Bytes(), pythonCt, pythonSignature)
	err = os.Remove("../../python/test_pythonIT.txt")

	jsCt, jsSignature, err := readTwoHexStringsFromFile("../../js/test_jsIT.txt")
	require.NoError(t, err, "Read file should not return an error")
	checkIT(t, plaintextBytes, userKey, contract.Bytes(), GetFuncSig(funcSig), ct.Bytes(), jsCt, jsSignature)
	err = os.Remove("../../js/test_jsIT.txt")
}

func checkIT(t *testing.T, plaintext, userKey, sender, addr, funcSig, ct, signature []byte) {
	// Verify the signature
	verified := VerifyIT(sender, addr, funcSig, ct, signature)
	assert.Equal(t, verified, true, "Verify signature should return true")

	decryptedText, err := Decrypt(userKey, ct[aes.BlockSize:], ct[:aes.BlockSize])
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Verify decrypted plaintext matches original message
	assert.Equal(t, plaintext, decryptedText[len(decryptedText)-len(plaintext):], "Decrypted plaintext should match original message")
}

func TestRSAEncryption(t *testing.T) {
	// Arrange
	// Generate key pair
	privateKey, publicKey, err := GenerateRSAKeyPair()
	require.NoError(t, err, "Generate RSA key pair should not return an error")

	// Message to encrypt
	plaintext := []byte("hello world")

	// Act and assert
	// Encrypt the plaintext
	cipher, err := EncryptRSA(publicKey, plaintext)
	require.NoError(t, err, "Encrypt should not return an error")

	// Decrypt the ciphertext
	decryptedText, err := DecryptRSA(privateKey, cipher)
	require.NoError(t, err, "Decrypt should not return an error")

	// Verify decrypted plaintext matches original message
	assert.Equal(t, plaintext, decryptedText, "Decrypted plaintext should match original message")
}

func readTwoHexStringsFromFile(path string) ([]byte, []byte, error) {
	data, err := readValFromFile(path)
	if err != nil {
		return nil, nil, err
	}

	// Split the data into two hex strings
	hexStrings := bytes.Split(data, []byte("\n"))

	// Convert the hex strings to bytes
	if len(hexStrings) != 2 {
		return nil, nil, fmt.Errorf("Expected two hex strings in the file")
	}

	privateKeyBytes, err := hex.DecodeString(string(hexStrings[0]))
	if err != nil {
		fmt.Println("Error decoding hex:", err)
		return nil, nil, err
	}

	publicKeyBytes, err := hex.DecodeString(string(hexStrings[1]))
	if err != nil {
		fmt.Println("Error decoding hex:", err)
		return nil, nil, err
	}

	return privateKeyBytes, publicKeyBytes, nil
}

func appendHexToFile(filename string, hexString string) error {
	// Check if the file exists
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		// Create the file if it doesn't exist
		_, err := os.Create(filename)
		if err != nil {
			return err
		}
	}

	// Open the file for appending with write permissions
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write the hexadecimal string to the file
	_, err = fmt.Fprintf(file, "%s\n", hexString)
	if err != nil {
		return err
	}

	return nil
}

// encryptMessage is a test helper function that reads RSA keys from a file, encrypts a plaintext message using the RSA public key,
// and then appends the encrypted message (in hexadecimal format) to the same file.
// It takes two parameters:
// t: The testing object, used for reporting errors in the test execution.
// keysFilePath: The path to the file containing the RSA keys.
// The function first reads the RSA keys from the file and checks for errors.
// It then defines a plaintext message to be encrypted.
// The plaintext message is encrypted using the RSA public key, and the function checks for errors.
// Finally, the encrypted message is converted to hexadecimal format and appended to the file containing the RSA keys.
func encryptMessage(t *testing.T, keysFilePath string) {
	// Reading and writing from/to a file simulates the communication between the evm (golang) and the user (python/js)
	_, key, err := readTwoHexStringsFromFile(keysFilePath)
	require.NoError(t, err, "Read RSA keys should not return an error")

	// Message to encrypt
	plaintext := []byte("hello world")

	// Decrypt the ciphertext
	ciphertext, err := EncryptRSA(key, plaintext)
	require.NoError(t, err, "Encrypt should not return an error")

	appendHexToFile(keysFilePath, "\n"+hex.EncodeToString(ciphertext))
}

// TestRSAEncryptionFixed is a test function that encrypts a fixed message using the RSA public keys generated by python and javascript tests.
// It uses the helper function encryptMessage to encrypt a plaintext message using RSA keys stored in files.
// The encrypted message is then appended to the same file.
// After the encryption is appended to the same file, the python and javascript tests check the encrypted message against the expected value.
// This test simulates the case that a user generates his own RSA keys in python or javascript tools and after that decrypts a message that was encrypted in the evm (which uses Go).
func TestRSAEncryptionFixed(t *testing.T) {
	encryptMessage(t, "../../python/soda_python_sdk/test_pythonRSAEncryption.txt")
	encryptMessage(t, "../../js/test_jsRSAEncryption.txt")
}

func checkFunctionSignature(t *testing.T, filePath string, expected []byte) {
	val, err := readHexValFromFile(filePath)
	require.NoError(t, err, "Read python value should not return an error")
	assert.Equal(t, expected, val, "hashed values should match")
	err = os.Remove(filePath)
}

func TestGetFuncSig(t *testing.T) {
	functionSig := "sign(bytes)"
	// Hash the function signature using Keccak-256 and return the first 4 bytes
	hash := GetFuncSig(functionSig)

	// Check that the python hashed value matches the Golang hashed value
	filePath := "../../python/soda_python_sdk/test_pythonFunctionKeccak.txt"
	checkFunctionSignature(t, filePath, hash)

	// Check that the js hashed value matches the Golang hashed value
	filePath = "../../js/test_jsFunctionKeccak.txt"
	checkFunctionSignature(t, filePath, hash)

}
