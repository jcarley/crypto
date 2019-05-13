package main

import (
	"fmt"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Encryptor", func() {

	Describe("EncryptStream", func() {
		It("Encrypts a stream", func() {
			currentDir, _ := os.Getwd()
			inFilePath := filepath.Join(currentDir, "data/encrypttestfile.md")
			inFile, _ := os.Open(inFilePath)

			passphrase := "this is a secret passphrase"
			encryptor := NewEncryptor()
			result, err := encryptor.EncryptStream(inFile, passphrase)
			Expect(err).To(BeNil())
			Expect(result.File).ToNot(BeNil())
			Expect(result.File.Name()).To(Equal(fmt.Sprintf("%s.enc", inFilePath)))
			Expect(result.File.Name()).To(BeARegularFile())

			outFile, _ := os.Open(result.File.Name())

			// Read the salt from the front of the file and verify it
			buffer := make([]byte, 32)
			bytesRead, err := outFile.Read(buffer)

			Expect(bytesRead).To(Equal(32))
			Expect(buffer).To(Equal(result.Salt))

			// cleanup after the test
			removeTestFile(result.File.Name())
		})
	})

	Describe("encryptedFilename", func() {
		It("Returns the original filename with enc appended to it", func() {
			currentDir, _ := os.Getwd()
			inFilePath := filepath.Join(currentDir, "data/encrypttestfile.md")
			inFile, _ := os.Open(inFilePath)

			actualFilename, err := encryptedFilename(inFile)
			Expect(err).To(BeNil())
			Expect(actualFilename).To(Equal(fmt.Sprintf("%s.enc", inFilePath)))
		})
	})

})
