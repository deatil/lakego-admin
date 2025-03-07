package mode

import (
    "testing"
    "crypto/aes"
    "encoding/hex"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_NCFB(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plo")
    iv := []byte("11injkijkol22plo")
    plaintext := []byte("kjinjkijkolkdplo")

    c, err := aes.NewCipher(key)
    assertNoError(err, "Test_NCFB-NewCipher")

    ofb := NewNCFBEncrypter(c, iv)
    ciphertext := make([]byte, len(plaintext))
    ofb.XORKeyStream(ciphertext, plaintext)

    ofb2 := NewNCFBDecrypter(c, iv)
    plaintext2 := make([]byte, len(ciphertext))
    ofb2.XORKeyStream(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "Test_NCFB-XORKeyStream")

    assertEqual(plaintext2, plaintext, "Test_NCFB-Equal")
}

func Test_NCFB_Check(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("fmY@T~st~Key_0123456789abcefghij")
    iv, _ := hex.DecodeString("9843b37efadf078c4962e2635c10f59b")
    plaintext := []byte("This is secret message.")

    c, err := aes.NewCipher(key)
    assertNoError(err, "Test_NCFB_Check-NewCipher")

    ciphertext1, _ := hex.DecodeString("ea9a3b3142e13e214defa2ecb2bb5347ef54052bcacfdc")

    ofb := NewNCFBEncrypter(c, iv)
    ciphertext := make([]byte, len(plaintext))
    ofb.XORKeyStream(ciphertext, plaintext)

    assertNotEmpty(ciphertext, "Test_NCFB_Check-XORKeyStream")

    assertEqual(ciphertext, ciphertext1, "Test_NCFB_Check-Equal")
}

func Test_NCFB_Check2(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("fmY@T~st~Key_0123456789abcefghij")
    iv, _ := hex.DecodeString("7cff6cda9c17029630794ad4511f3083")
    plaintext := []byte("This is secret message.")

    c, err := aes.NewCipher(key)
    assertNoError(err, "Test_NCFB_Check2-NewCipher")

    ciphertext, _ := hex.DecodeString("0f94fafb395c80ada7ff0a650d66b060c3296a78e708c1")

    ofb := NewNCFBDecrypter(c, iv)
    plaintext2 := make([]byte, len(ciphertext))
    ofb.XORKeyStream(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "Test_NCFB_Check2-XORKeyStream")

    assertEqual(plaintext2, plaintext, "Test_NCFB_Check2-Equal")
}
