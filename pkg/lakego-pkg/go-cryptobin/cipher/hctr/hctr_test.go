package hctr

import (
    "testing"
    "crypto/aes"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_HCTR(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plo")
    plaintext := []byte("kjinjkijkolkdplo")

    tweak := []byte("kkinjkijeel2pass")
    hkey := []byte("11injkijkol22plo")

    c, err := aes.NewCipher(key)
    assertError(err, "NewHCTR")

    mode := NewHCTR(c, tweak, hkey)
    ciphertext := make([]byte, len(plaintext))
    mode.Encrypt(ciphertext, plaintext)

    mode2 := NewHCTR(c, tweak, hkey)
    plaintext2 := make([]byte, len(ciphertext))
    mode2.Decrypt(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "NewHCTR")

    assertEqual(plaintext2, plaintext, "NewHCTR-Equal")
}
