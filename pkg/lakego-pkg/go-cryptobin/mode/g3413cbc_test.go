package mode

import (
    "testing"
    "encoding/hex"

    "github.com/deatil/go-cryptobin/cipher/kuznyechik"
    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_G3413CBC(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plokkinjkijeel22plo")
    iv := []byte("t1i-66ij11injki33njknjeel22plovk")
    plaintext := []byte("y7u9jkijkolkdp123456fthnjukolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplobbbbkijkolkdpaaaaaaaaaaaaaaaadplokjinjkijkyyyyyyjinjkijkolkdplokjinjkijkolkdplokjinjkijkolk5555lokjinjki33333333lokjinjkijkolk")

    c, err := kuznyechik.NewCipher(key)
    assertNoError(err, "Test_G3413CBC-NewCipher")

    cbc := NewG3413CBCEncrypter(c, iv)
    ciphertext := make([]byte, len(plaintext))
    cbc.CryptBlocks(ciphertext, plaintext)

    cbc2 := NewG3413CBCDecrypter(c, iv)
    plaintext2 := make([]byte, len(ciphertext))
    cbc2.CryptBlocks(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "Test_G3413CBC-CryptBlocks")

    assertEqual(string(plaintext2), string(plaintext), "Test_G3413CBC-Equal")
}

func Test_G3413CBC_1(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plokkinjkijeel22plo")
    iv := []byte("t1i-66ij11injki33njknjeel22plovk")
    plaintext := []byte("y7u9jkijkolkdp12")

    c, err := kuznyechik.NewCipher(key)
    assertNoError(err, "Test_G3413CBC_1-NewCipher")

    cbc := NewG3413CBCEncrypter(c, iv)
    ciphertext := make([]byte, len(plaintext))
    cbc.CryptBlocks(ciphertext, plaintext)

    cbc2 := NewG3413CBCDecrypter(c, iv)
    plaintext2 := make([]byte, len(ciphertext))
    cbc2.CryptBlocks(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "Test_G3413CBC_1-CryptBlocks")

    assertEqual(string(plaintext2), string(plaintext), "Test_G3413CBC_1-Equal")
}

func Test_G3413CBC_2(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plokkinjkijeel22plo")
    iv := []byte("t1i-66ij11injki33njknjeel22plovk")
    plaintext := []byte("y7u9jkijkolkdp12y7i9j33jkogkdp12")

    c, err := kuznyechik.NewCipher(key)
    assertNoError(err, "Test_G3413CBC_1-NewCipher")

    cbc := NewG3413CBCEncrypter(c, iv)
    ciphertext := make([]byte, len(plaintext))
    cbc.CryptBlocks(ciphertext, plaintext)

    cbc2 := NewG3413CBCDecrypter(c, iv)
    plaintext2 := make([]byte, len(ciphertext))
    cbc2.CryptBlocks(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "Test_G3413CBC_1-CryptBlocks")

    assertEqual(string(plaintext2), string(plaintext), "Test_G3413CBC_1-Equal")
}

func Test_G3413CBC_Check(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key, _ := hex.DecodeString("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
    iv, _ := hex.DecodeString("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")
    plaintext, _ := hex.DecodeString("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011")

    c, err := kuznyechik.NewCipher(key)
    assertNoError(err, "Test_G3413CBC_Check-NewCipher")

    ciphertext1, _ := hex.DecodeString("689972d4a085fa4d90e52e3d6d7dcc272826e661b478eca6af1e8e448d5ea5acfe7babf1e91999e85640e8b0f49d90d0167688065a895c631a2d9a1560b63970")

    cbc := NewG3413CBCEncrypter(c, iv)
    ciphertext := make([]byte, len(plaintext))
    cbc.CryptBlocks(ciphertext, plaintext)

    assertNotEmpty(ciphertext, "Test_G3413CBC_Check-XORKeyStream")

    assertEqual(ciphertext, ciphertext1, "Test_G3413CBC_Check-Equal")
}

func Test_G3413CBC_Check_2(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key, _ := hex.DecodeString("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
    iv, _ := hex.DecodeString("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")
    plaintext, _ := hex.DecodeString("689972d4a085fa4d90e52e3d6d7dcc272826e661b478eca6af1e8e448d5ea5acfe7babf1e91999e85640e8b0f49d90d0167688065a895c631a2d9a1560b63970")

    c, err := kuznyechik.NewCipher(key)
    assertNoError(err, "Test_G3413CBC_Check_2-NewCipher")

    ciphertext1, _ := hex.DecodeString("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011")

    cbc := NewG3413CBCDecrypter(c, iv)
    ciphertext := make([]byte, len(plaintext))
    cbc.CryptBlocks(ciphertext, plaintext)

    assertNotEmpty(ciphertext, "Test_G3413CBC_Check_2-XORKeyStream")

    assertEqual(ciphertext, ciphertext1, "Test_G3413CBC_Check_2-Equal")
}
