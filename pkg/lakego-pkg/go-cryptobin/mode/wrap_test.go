package mode

import (
    "testing"
    "crypto/aes"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_Wrap(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plo")
    iv := []byte("11injkij")
    plaintext := []byte("kjinjkijkolkdplo")

    c, err := aes.NewCipher(key)
    assertNoError(err, "Test_Wrap")

    mode := NewWrapEncrypter(c, iv)
    ciphertext := make([]byte, len(plaintext)+8)
    mode.CryptBlocks(ciphertext, plaintext)

    mode2 := NewWrapDecrypter(c, iv)
    plaintext2 := make([]byte, len(ciphertext)-8)
    mode2.CryptBlocks(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "Test_Wrap")

    assertEqual(plaintext2, plaintext, "Test_Wrap-Equal")
}

func Test_WrapWithNoIV(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plo")
    plaintext := []byte("kjinjkijkolkdplo")

    c, err := aes.NewCipher(key)
    assertNoError(err, "Test_WrapWithNoIV")

    mode := NewWrapEncrypter(c, nil)
    ciphertext := make([]byte, len(plaintext)+8)
    mode.CryptBlocks(ciphertext, plaintext)

    mode2 := NewWrapDecrypter(c, nil)
    plaintext2 := make([]byte, len(ciphertext)-8)
    mode2.CryptBlocks(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "Test_WrapWithNoIV")

    assertEqual(plaintext2, plaintext, "Test_WrapWithNoIV-Equal")
}

func Test_WrapLong(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plo")
    iv := []byte("11injkij")
    plaintext := []byte("kjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplo")

    c, err := aes.NewCipher(key)
    assertNoError(err, "Test_WrapLong")

    mode := NewWrapEncrypter(c, iv)
    ciphertext := make([]byte, len(plaintext)+8)
    mode.CryptBlocks(ciphertext, plaintext)

    mode2 := NewWrapDecrypter(c, iv)
    plaintext2 := make([]byte, len(ciphertext)-8)
    mode2.CryptBlocks(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "Test_WrapLong")

    assertEqual(plaintext2, plaintext, "Test_WrapLong-Equal")
}

func Test_WrapPad(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plo")
    iv := []byte("jkij")
    plaintext := []byte("srftyf57")

    c, err := aes.NewCipher(key)
    assertNoError(err, "Test_WrapPad")

    mode := NewWrapPadEncrypter(c, iv)
    ciphertext := make([]byte, len(plaintext)+8)
    mode.CryptBlocks(ciphertext, plaintext)

    mode2 := NewWrapPadDecrypter(c, iv)
    plaintext2 := make([]byte, len(ciphertext)-8)
    mode2.CryptBlocks(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "Test_WrapPad")

    assertEqual(plaintext2, plaintext, "Test_WrapPad-Equal")
}

func Test_WrapPadWithNoIV(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plo")
    plaintext := []byte("srftyf57")

    c, err := aes.NewCipher(key)
    assertNoError(err, "Test_WrapPadWithNoIV")

    mode := NewWrapPadEncrypter(c, nil)
    ciphertext := make([]byte, len(plaintext)+8)
    mode.CryptBlocks(ciphertext, plaintext)

    mode2 := NewWrapPadDecrypter(c, nil)
    plaintext2 := make([]byte, len(ciphertext)-8)
    mode2.CryptBlocks(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "Test_WrapPadWithNoIV")

    assertEqual(plaintext2, plaintext, "Test_WrapPadWithNoIV-Equal")
}

func Test_WrapPadLong(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plo")
    iv := []byte("jkij")
    plaintext := []byte("kjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplo")

    c, err := aes.NewCipher(key)
    assertNoError(err, "Test_WrapPadLong")

    mode := NewWrapPadEncrypter(c, iv)
    ciphertext := make([]byte, len(plaintext)+8)
    mode.CryptBlocks(ciphertext, plaintext)

    mode2 := NewWrapPadDecrypter(c, iv)
    plaintext2 := make([]byte, len(ciphertext)-8)
    mode2.CryptBlocks(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "Test_WrapPadLong")

    assertEqual(plaintext2, plaintext, "Test_WrapPadLong-Equal")
}

/* aes key */
var test_wrap_key = []byte{
    0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
    0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
    0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f,
}

/* Unique initialisation vector */
var test_wrap_iv = []byte{
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84,
    0x99, 0xaa, 0x3e, 0x68,
}

/* Example plaintext to encrypt */
var test_wrap_pt = []byte{
    0xad, 0x4f, 0xc9, 0xfc, 0x77, 0x69, 0xc9, 0xea, 0xfc, 0xdf, 0x00, 0xac,
    0x34, 0xec, 0x40, 0xbc, 0x28, 0x3f, 0xa4, 0x5e, 0xd8, 0x99, 0xe4, 0x5d,
    0x5e, 0x7a, 0xc4, 0xe6, 0xca, 0x7b, 0xa5, 0xb7,
}

/* Expected ciphertext value */
var test_wrap_ct = []byte{
    0x97, 0x99, 0x55, 0xca, 0xf6, 0x3e, 0x95, 0x54, 0x39, 0xd6, 0xaf, 0x63, 0xff, 0x2c, 0xe3, 0x96,
    0xf7, 0x0d, 0x2c, 0x9c, 0xc7, 0x43, 0xc0, 0xb6, 0x31, 0x43, 0xb9, 0x20, 0xac, 0x6b, 0xd3, 0x67,
    0xad, 0x01, 0xaf, 0xa7, 0x32, 0x74, 0x26, 0x92,
}

func Test_Wrap_Check(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    key := test_wrap_key
    iv := test_wrap_iv
    plaintext1 := test_wrap_pt
    ciphertext1 := test_wrap_ct

    c, err := aes.NewCipher(key)
    assertNoError(err, "Test_Wrap_Check")

    t.Run("NewWrapEncrypter", func(t *testing.T) {
        mode := NewWrapEncrypter(c, iv)
        ciphertext := make([]byte, len(plaintext1)+8)
        mode.CryptBlocks(ciphertext, plaintext1)

        assertEqual(ciphertext, ciphertext1, "Test_Wrap_Check-Equal")
    })

    t.Run("NewWrapDecrypter", func(t *testing.T) {
        mode := NewWrapDecrypter(c, iv)
        plaintext := make([]byte, len(ciphertext1)-8)
        mode.CryptBlocks(plaintext, ciphertext1)

        assertEqual(plaintext, plaintext1, "Test_Wrap_Check-Equal")
    })
}
