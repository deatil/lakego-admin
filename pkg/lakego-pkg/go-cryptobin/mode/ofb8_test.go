package mode

import (
    "testing"
    "crypto/aes"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_OFB8(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plo")
    iv := []byte("11injkijkol22plo")
    plaintext := []byte("kjinjkijkolkdplo")

    c, err := aes.NewCipher(key)
    assertNoError(err, "Test_OFB8")

    mode := NewOFB8(c, iv)
    ciphertext := make([]byte, len(plaintext))
    mode.XORKeyStream(ciphertext, plaintext)

    mode2 := NewOFB8(c, iv)
    plaintext2 := make([]byte, len(ciphertext))
    mode2.XORKeyStream(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "Test_OFB8")

    assertEqual(plaintext2, plaintext, "Test_OFB8-Equal")
}
