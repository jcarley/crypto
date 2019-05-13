package main

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/scrypt"
)

type Decryptor struct {
}

func NewDecryptor() *Decryptor {
	return &Decryptor{}
}

func (this *Decryptor) DecryptStream(file *os.File, passphrase string) (*os.File, error) {

	salt := make([]byte, saltSize)
	_, err := file.Read(salt)
	if err != nil {
		return nil, err
	}

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

	filename, err := decryptedFilename(file)
	if err != nil {
		return nil, err
	}

	outFile, err := os.Create(filename)
	defer outFile.Close()
	if err != nil {
		return nil, err
	}

	reader := &cipher.StreamReader{S: stream, R: file}
	// Copy the input to the output buffer, encrypting as we go.
	if _, err := io.Copy(outFile, reader); err != nil {
		return nil, err
	}

	// result.File = outFile

	return outFile, nil
}

func decryptedFilename(file *os.File) (string, error) {
	return strings.TrimSuffix(file.Name(), ".enc"), nil
}
