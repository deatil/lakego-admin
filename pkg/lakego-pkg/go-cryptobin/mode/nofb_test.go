package cipher

import (
    "testing"
    "crypto/aes"
    "encoding/hex"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_NOFB(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plo")
    iv := []byte("11injkijkol22plo")
    plaintext := []byte("kjinjkijkolkdplo")

    c, err := aes.NewCipher(key)
    assertNoError(err, "Test_NOFB-NewCipher")

    ofb := NewNOFB(c, iv)
    ciphertext := make([]byte, len(plaintext))
    ofb.XORKeyStream(ciphertext, plaintext)

    ofb2 := NewNOFB(c, iv)
    plaintext2 := make([]byte, len(ciphertext))
    ofb2.XORKeyStream(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "Test_NOFB-XORKeyStream")

    assertEqual(plaintext2, plaintext, "Test_NOFB-Equal")
}

func Test_NOFB_Check(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("fmY@T~st~Key_0123456789abcefghij")
    iv, _ := hex.DecodeString("7094e688c696aa1b50369209d484c4ac")
    plaintext := []byte("This is secret message.")

    c, err := aes.NewCipher(key)
    assertNoError(err, "Test_NOFB_Check-NewCipher")

    ciphertext1, _ := hex.DecodeString("835ba2d052242fb185965b8ca8e2e45fe3ad474275537e")

    ofb := NewNOFB(c, iv)
    ciphertext := make([]byte, len(plaintext))
    ofb.XORKeyStream(ciphertext, plaintext)

    assertNotEmpty(ciphertext, "Test_NOFB_Check-XORKeyStream")

    assertEqual(ciphertext, ciphertext1, "Test_NOFB_Check-Equal")
}

func Test_NOFB_Check2(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("fmY@T~st~Key_0123456789abcefghij")
    iv, _ := hex.DecodeString("7b2c173022a52e72ca351743fc80f7a2")
    plaintext := []byte("This is secret message.")

    c, err := aes.NewCipher(key)
    assertNoError(err, "Test_NOFB_Check2-NewCipher")

    ciphertext, _ := hex.DecodeString("efe7e86770916421fdc56a4393bf422ceb9b7371fccfdd")

    ofb := NewNOFB(c, iv)
    plaintext2 := make([]byte, len(ciphertext))
    ofb.XORKeyStream(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "Test_NOFB_Check2-XORKeyStream")

    assertEqual(plaintext2, plaintext, "Test_NOFB_Check2-Equal")
}
