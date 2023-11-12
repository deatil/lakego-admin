package pbes1

import (
    "testing"
    "crypto/rand"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_EncryptPKCS8PrivateKey(t *testing.T) {
    test_EncryptPKCS8PrivateKey(t, "SHA1And3DES", SHA1And3DES)
    test_EncryptPKCS8PrivateKey(t, "SHA1And2DES", SHA1And2DES)
    test_EncryptPKCS8PrivateKey(t, "SHA1AndRC2_128", SHA1AndRC2_128)
    test_EncryptPKCS8PrivateKey(t, "SHA1AndRC2_40", SHA1AndRC2_40)
    test_EncryptPKCS8PrivateKey(t, "SHA1AndRC4_128", SHA1AndRC4_128)
    test_EncryptPKCS8PrivateKey(t, "SHA1AndRC4_40", SHA1AndRC4_40)

    test_EncryptPKCS8PrivateKey(t, "MD2AndDES", MD2AndDES)
    test_EncryptPKCS8PrivateKey(t, "MD2AndRC2_64", MD2AndRC2_64)
    test_EncryptPKCS8PrivateKey(t, "MD5AndDES", MD5AndDES)
    test_EncryptPKCS8PrivateKey(t, "MD5AndRC2_64", MD5AndRC2_64)
    test_EncryptPKCS8PrivateKey(t, "SHA1AndDES", SHA1AndDES)
    test_EncryptPKCS8PrivateKey(t, "SHA1AndRC2_64", SHA1AndRC2_64)
}

func test_EncryptPKCS8PrivateKey(t *testing.T, name string, cipher Cipher) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    data := "test-data"
    pass := "test-pass"

    t.Run(name, func(t *testing.T) {
        block, err := EncryptPKCS8PrivateKey(rand.Reader, "ENCRYPTED PRIVATE KEY", []byte(data), []byte(pass), cipher)
        assertError(err, "EncryptPKCS8PrivateKey-EN")
        assertNotEmpty(block.Bytes, "EncryptPKCS8PrivateKey-EN")

        deData, err := DecryptPKCS8PrivateKey(block.Bytes, []byte(pass))
        assertError(err, "EncryptPKCS8PrivateKey-DE")
        assertNotEmpty(deData, "EncryptPKCS8PrivateKey-DE")

        assertEqual(string(deData), data, "EncryptPKCS8PrivateKey")
    })
}

// ===========

func Test_EncryptPKCS8Privatekey(t *testing.T) {
    test_EncryptPKCS8Privatekey(t, "SHA1And3DES", SHA1And3DES)
    test_EncryptPKCS8Privatekey(t, "SHA1And2DES", SHA1And2DES)
    test_EncryptPKCS8Privatekey(t, "SHA1AndRC2_128", SHA1AndRC2_128)
    test_EncryptPKCS8Privatekey(t, "SHA1AndRC2_40", SHA1AndRC2_40)
    test_EncryptPKCS8Privatekey(t, "SHA1AndRC4_128", SHA1AndRC4_128)
    test_EncryptPKCS8Privatekey(t, "SHA1AndRC4_40", SHA1AndRC4_40)

    test_EncryptPKCS8Privatekey(t, "MD2AndDES", MD2AndDES)
    test_EncryptPKCS8Privatekey(t, "MD2AndRC2_64", MD2AndRC2_64)
    test_EncryptPKCS8Privatekey(t, "MD5AndDES", MD5AndDES)
    test_EncryptPKCS8Privatekey(t, "MD5AndRC2_64", MD5AndRC2_64)
    test_EncryptPKCS8Privatekey(t, "SHA1AndDES", SHA1AndDES)
    test_EncryptPKCS8Privatekey(t, "SHA1AndRC2_64", SHA1AndRC2_64)
}

func test_EncryptPKCS8Privatekey(t *testing.T, name string, cipher Cipher) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    data := "test-data"
    pass := "test-pass"

    t.Run(name, func(t *testing.T) {
        block, err := EncryptPKCS8PrivateKey(rand.Reader, "ENCRYPTED PRIVATE KEY", []byte(data), []byte(pass), cipher)
        assertError(err, "EncryptPKCS8PrivateKey-EN")
        assertNotEmpty(block.Bytes, "EncryptPKCS8PrivateKey-EN")

        deData, err := DecryptPKCS8PrivateKey(block.Bytes, []byte(pass))
        assertError(err, "EncryptPKCS8PrivateKey-DE")
        assertNotEmpty(deData, "EncryptPKCS8PrivateKey-DE")

        assertEqual(string(deData), data, "EncryptPKCS8PrivateKey")
    })
}
