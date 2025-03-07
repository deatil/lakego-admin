package mode

import (
    "testing"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/cipher/gost"
    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_GCFB(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plokkinjkijeel22plo")
    iv := []byte("11injkij")
    plaintext := []byte("kjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplo")

    cip := func(key []byte) (cipher.Block, error) {
        return gost.NewCipher(key, gost.SboxGost2814789TestParamSet)
    }

    cfb := NewGCFBEncrypter(cip, key, iv)
    ciphertext := make([]byte, len(plaintext))
    cfb.XORKeyStream(ciphertext, plaintext)

    cfb2 := NewGCFBDecrypter(cip, key, iv)
    plaintext2 := make([]byte, len(ciphertext))
    cfb2.XORKeyStream(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "Test_GCFB-XORKeyStream")

    assertEqual(string(plaintext2), string(plaintext), "Test_GCFB-Equal")
}
