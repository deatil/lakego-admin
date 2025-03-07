package mode

import (
    "testing"
    "encoding/hex"

    "github.com/deatil/go-cryptobin/cipher/kuznyechik"
    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_G3413OFB(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plokkinjkijeel22plo")
    iv := []byte("11injkij11injkijinjkijeel22plokk")
    plaintext := []byte("kjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplo")

    c, err := kuznyechik.NewCipher(key)
    assertNoError(err, "Test_G3413OFB-NewCipher")

    ofb := NewG3413OFB(c, iv)
    ciphertext := make([]byte, len(plaintext))
    ofb.XORKeyStream(ciphertext, plaintext)

    ofb2 := NewG3413OFB(c, iv)
    plaintext2 := make([]byte, len(ciphertext))
    ofb2.XORKeyStream(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "Test_G3413OFB-XORKeyStream")

    assertEqual(plaintext2, plaintext, "Test_G3413OFB-Equal")
}

func Test_G3413OFB_Check(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key, _ := hex.DecodeString("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
    iv, _ := hex.DecodeString("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")
    plaintext, _ := hex.DecodeString("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011")

    c, err := kuznyechik.NewCipher(key)
    assertNoError(err, "Test_G3413OFB_Check-NewCipher")

    ciphertext1, _ := hex.DecodeString("81800a59b1842b24ff1f795e897abd95ed5b47a7048cfab48fb521369d9326bf66a257ac3ca0b8b1c80fe7fc10288a13203ebbc066138660a0292243f6903150")

    ofb := NewG3413OFB(c, iv)
    ciphertext := make([]byte, len(plaintext))
    ofb.XORKeyStream(ciphertext, plaintext)

    assertNotEmpty(ciphertext, "Test_G3413OFB_Check-XORKeyStream")

    assertEqual(ciphertext, ciphertext1, "Test_G3413OFB_Check-Equal")
}
