package cipher

import (
    "testing"
    "crypto/aes"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_OFBNLF(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plo")
    iv := []byte("11injkijkol22plo")
    plaintext := []byte("kjinjkijkolkdplo")

    c, err := aes.NewCipher(key)
    assertError(err, "NewOFBNLF")

    mode := NewOFBNLFEncrypter(c, aes.NewCipher, iv)
    ciphertext := make([]byte, len(plaintext))
    mode.CryptBlocks(ciphertext, plaintext)

    mode2 := NewOFBNLFDecrypter(c, aes.NewCipher, iv)
    plaintext2 := make([]byte, len(ciphertext))
    mode2.CryptBlocks(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "NewOFBNLF")

    assertEqual(plaintext2, plaintext, "NewOFBNLF-Equal")
}
