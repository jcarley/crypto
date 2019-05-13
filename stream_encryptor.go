package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/scrypt"
)

const (
	// keySize is the size of a NaCl secret key.
	keySize = 32

	// nonceSize is the size of a NaCl nonce.
	nonceSize = 24

	// saltSize is the size of the scrypt salt.
	saltSize = 32
)

var (
	// IterationsHigh is the recommended number of iterations for
	// file encryption according to the scrypt docs.
	IterationsHigh = 1048576

	// IterationsLow is twice the number of iterations for interactive
	// encryption as specified in the scrypt docs.
	IterationsLow = 32768

	// Iterations contains the number of iterations to be used by
	// filecrypt; the default is the standard filecrypt number.
	Iterations = IterationsHigh
)

type EncryptResult struct {
	Salt      []byte
	File      *os.File
	Signature []byte
}

type Encryptor struct {
}

func NewEncryptor() *Encryptor {
	return &Encryptor{}
}

func (this *Encryptor) EncryptStream(file *os.File, passphrase string) (*EncryptResult, error) {

	// Note that this example is simplistic in that it omits any
	// authentication of the encrypted data. If you were actually to use
	// StreamReader in this manner, an attacker could flip arbitrary bits in
	// the decrypted result.

	result := &EncryptResult{}

	salt, err := randBytes(saltSize)
	if err != nil {
		return nil, err
	}
	result.Salt = salt

	dk, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		panic(err)
	}

	block, err := aes.NewCipher(dk)
	if err != nil {
		panic(err)
	}

	// If the key is unique for each ciphertext, then it's ok to use a zero IV.
	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])

	filename, err := encryptedFilename(file)
	if err != nil {
		return nil, err
	}

	outFile, err := os.Create(filename)
	defer outFile.Close()
	if err != nil {
		return nil, err
	}

	// we write the salt at the beginning of the file so that we can retrieve it
	// during the decryption process
	outFile.Write(salt)

	writer := &cipher.StreamWriter{S: stream, W: outFile}
	// Copy the input to the output buffer, encrypting as we go.
	if _, err := io.Copy(writer, file); err != nil {
		return nil, err
	}

	result.File = outFile

	return result, nil
}

func encryptedFilename(file *os.File) (string, error) {
	return fmt.Sprintf("%s.enc", file.Name()), nil
}

// deriveKey generates a new NaCl key from a passphrase and salt.
func deriveKey(pass, salt []byte) *[keySize]byte {
	var naclKey = new([keySize]byte)

	// Key only fails with invalid scrypt params.
	key, _ := scrypt.Key(pass, salt, Iterations, 8, 1, keySize)

	copy(naclKey[:], key)
	Zero(key)
	return naclKey
}

func randBytes(size int) ([]byte, error) {
	r := make([]byte, size)
	_, err := rand.Read(r)
	return r, err
}

// Zero attempts to zeroise its input.
func Zero(in []byte) {
	for i := 0; i < len(in); i++ {
		in[i] = 0
	}
}
