package cipher

import (
    "testing"
    "encoding/hex"

    "github.com/deatil/go-cryptobin/cipher/kuznyechik"
    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_G3413CTR(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plokkinjkijeel22plo")
    iv := []byte("t1i-66ij")
    plaintext := []byte("y7u9jkijkolkdp123456fthnjukolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplobbbbkijkolkdpaaaaaaaaaaaaaaaadplokjinjkijkyyyyyyjinjkijkolkdplokjinjkijkolkdplokjinjkijkolk5555lokjinjki33333333lokjinjkijkolk")

    c, err := kuznyechik.NewCipher(key)
    assertError(err, "Test_G3413CTR-NewCipher")

    cbc := NewG3413CTR(c, iv)
    ciphertext := make([]byte, len(plaintext))
    cbc.XORKeyStream(ciphertext, plaintext)

    cbc2 := NewG3413CTR(c, iv)
    plaintext2 := make([]byte, len(ciphertext))
    cbc2.XORKeyStream(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "Test_G3413CTR-XORKeyStream")

    assertEqual(string(plaintext2), string(plaintext), "Test_G3413CTR-Equal")
}

func Test_G3413CTR_Check(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key, _ := hex.DecodeString("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
    iv, _ := hex.DecodeString("1234567890abcef0")
    plaintext, _ := hex.DecodeString("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011")

    c, err := kuznyechik.NewCipher(key)
    assertError(err, "Test_G3413CTR_Check-NewCipher")

    ciphertext1, _ := hex.DecodeString("f195d8bec10ed1dbd57b5fa240bda1b885eee733f6a13e5df33ce4b33c45dee4a5eae88be6356ed3d5e877f13564a3a5cb91fab1f20cbab6d1c6d15820bdba73")

    cbc := NewG3413CTR(c, iv)
    ciphertext := make([]byte, len(plaintext))
    cbc.XORKeyStream(ciphertext, plaintext)

    assertNotEmpty(ciphertext, "Test_G3413CTR_Check-XORKeyStream")

    assertEqual(ciphertext, ciphertext1, "Test_G3413CTR_Check-Equal")
}

func Test_G3413CTR_Check_2(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key, _ := hex.DecodeString("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
    iv, _ := hex.DecodeString("1234567890abcef0")
    plaintext, _ := hex.DecodeString("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011")

    c, err := kuznyechik.NewCipher(key)
    assertError(err, "Test_G3413CTR_Check_2-NewCipher")

    ciphertext1, _ := hex.DecodeString("f1a787ad3a88f9a0bc735293f98c12c3eb31621b9b2e6461c7ef73a2e6a6b1793ddf722f7b1d22a722ec4d3edbc313bcd356b313d37af9e5ef934fa223c13fe2")

    cbc := NewG3413CTRWithBitBlockSize(c, iv, 8)
    ciphertext := make([]byte, len(plaintext))
    cbc.XORKeyStream(ciphertext, plaintext)

    assertNotEmpty(ciphertext, "Test_G3413CTR_Check_2-XORKeyStream")

    assertEqual(ciphertext, ciphertext1, "Test_G3413CTR_Check_2-Equal")
}
