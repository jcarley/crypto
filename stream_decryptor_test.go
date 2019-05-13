package main

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Decryptor", func() {

	Describe("DecryptStream", func() {
		It("Decrypts a stream", func() {
			currentDir, _ := os.Getwd()
			inFilePath := filepath.Join(currentDir, "data")
			inFileName := "decrypttestfile.md.enc"
			inFile, _ := os.Open(filepath.Join(inFilePath, inFileName))

			passphrase := "this is a secret passphrase"
			decryptor := NewDecryptor()
			outFile, err := decryptor.DecryptStream(inFile, passphrase)
			Expect(err).To(BeNil())
			Expect(outFile).ToNot(BeNil())
			Expect(outFile.Name()).To(Equal(filepath.Join(inFilePath, "decrypttestfile.md")))
			Expect(outFile.Name()).To(BeARegularFile())

			// cleanup after the test
			removeTestFile(outFile.Name())
		})
	})

	Describe("decryptedFilename", func() {
		It("Returns the input filename with out the enc extension", func() {
			currentDir, _ := os.Getwd()
			inFilePath := filepath.Join(currentDir, "data")
			inFileName := "decrypttestfile.md.enc"
			inFile, _ := os.Open(filepath.Join(inFilePath, inFileName))

			actualFilename, err := decryptedFilename(inFile)
			Expect(err).To(BeNil())
			Expect(actualFilename).To(Equal(filepath.Join(inFilePath, "decrypttestfile.md")))
		})
	})

})

func removeTestFile(filename string) {
	os.Remove(filename)
}
