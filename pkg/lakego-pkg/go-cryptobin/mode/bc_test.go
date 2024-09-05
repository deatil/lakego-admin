package cipher

import (
    "testing"
    "crypto/aes"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_BC(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plo")
    iv := []byte("11injkijkol22plo")
    plaintext := []byte("kjinjkijkolkdplo")

    c, err := aes.NewCipher(key)
    assertError(err, "NewBCEncrypter")

    mode := NewBCEncrypter(c, iv)
    ciphertext := make([]byte, len(plaintext))
    mode.CryptBlocks(ciphertext, plaintext)

    mode2 := NewBCDecrypter(c, iv)
    plaintext2 := make([]byte, len(ciphertext))
    mode2.CryptBlocks(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "NewBCEncrypter")

    assertEqual(plaintext2, plaintext, "NewBCEncrypter-Equal")
}
