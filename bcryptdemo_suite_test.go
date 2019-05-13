package main_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestBcryptdemo(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Bcryptdemo Suite")
}
