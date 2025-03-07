package mode

import (
    "testing"
    "encoding/hex"

    "github.com/deatil/go-cryptobin/cipher/kuznyechik"
    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_G3413CFB(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plokkinjkijeel22plo")
    iv := []byte("t1i-66ij11injki33njknjeel22plovk")
    plaintext := []byte("y7u9jkijkolkdp123456fthnjukolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplobbbbkijkolkdpaaaaaaaaaaaaaaaadplokjinjkijkyyyyyyjinjkijkolkdplokjinjkijkolkdplokjinjkijkolk5555lokjinjki33333333lokjinjkijkolk")

    c, err := kuznyechik.NewCipher(key)
    assertNoError(err, "Test_G3413CFB-NewCipher")

    cbc := NewG3413CFBEncrypter(c, iv)
    ciphertext := make([]byte, len(plaintext))
    cbc.XORKeyStream(ciphertext, plaintext)

    cbc2 := NewG3413CFBDecrypter(c, iv)
    plaintext2 := make([]byte, len(ciphertext))
    cbc2.XORKeyStream(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "Test_G3413CFB-XORKeyStream")

    assertEqual(string(plaintext2), string(plaintext), "Test_G3413CFB-Equal")
}

func Test_G3413CFB_Check(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key, _ := hex.DecodeString("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
    iv, _ := hex.DecodeString("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")
    plaintext, _ := hex.DecodeString("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011")

    c, err := kuznyechik.NewCipher(key)
    assertNoError(err, "Test_G3413CFB_Check-NewCipher")

    ciphertext1, _ := hex.DecodeString("81800a59b1842b24ff1f795e897abd95ed5b47a7048cfab48fb521369d9326bf79f2a8eb5cc68d38842d264e97a238b54ffebecd4e922de6c75bd9dd44fbf4d1")

    cbc := NewG3413CFBEncrypter(c, iv)
    ciphertext := make([]byte, len(plaintext))
    cbc.XORKeyStream(ciphertext, plaintext)

    assertNotEmpty(ciphertext, "Test_G3413CFB_Check-XORKeyStream")

    assertEqual(ciphertext, ciphertext1, "Test_G3413CFB_Check-Equal")
}

func Test_G3413CFB_Check_2(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key, _ := hex.DecodeString("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
    iv, _ := hex.DecodeString("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")
    plaintext, _ := hex.DecodeString("81800a59b1842b24ff1f795e897abd95ed5b47a7048cfab48fb521369d9326bf79f2a8eb5cc68d38842d264e97a238b54ffebecd4e922de6c75bd9dd44fbf4d1")

    c, err := kuznyechik.NewCipher(key)
    assertNoError(err, "Test_G3413CFB_Check_2-NewCipher")

    ciphertext1, _ := hex.DecodeString("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011")

    cbc := NewG3413CFBDecrypter(c, iv)
    ciphertext := make([]byte, len(plaintext))
    cbc.XORKeyStream(ciphertext, plaintext)

    assertNotEmpty(ciphertext, "Test_G3413CFB_Check_2-XORKeyStream")

    assertEqual(ciphertext, ciphertext1, "Test_G3413CFB_Check_2-Equal")
}

func Test_G3413CFB_Check_3(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key, _ := hex.DecodeString("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
    iv, _ := hex.DecodeString("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")
    plaintext, _ := hex.DecodeString("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011")

    c, err := kuznyechik.NewCipher(key)
    assertNoError(err, "Test_G3413CFB_Check_3-NewCipher")

    ciphertext1, _ := hex.DecodeString("819b19c5867e61f1cf1b16f664f66e46ed8fcb82b1110b1e7ec03bfa6611f2eabd7a32363691cbdc3bbe403bc80552d822c2cdf483981cd71d5595453d7f057d")

    cbc := NewG3413CFBEncrypterWithBitBlockSize(c, iv, 8)
    ciphertext := make([]byte, len(plaintext))
    cbc.XORKeyStream(ciphertext, plaintext)

    assertNotEmpty(ciphertext, "Test_G3413CFB_Check_3-XORKeyStream")

    assertEqual(ciphertext, ciphertext1, "Test_G3413CFB_Check_3-Equal")
}
