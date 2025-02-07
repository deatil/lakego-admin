package pbes1

import (
    "testing"
    "crypto/rand"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func test_cipher(t *testing.T, cipher Cipher, name string, key []byte) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    plaintext := []byte("test data")

    endata, parm, err := cipher.Encrypt(rand.Reader, key, plaintext)
    assertNoError(err, name + "-Encrypt")
    assertNotEmpty(endata, name + "-endata")
    assertNotEmpty(parm, name + "-parm")

    dedata, err := cipher.Decrypt(key, parm, endata)
    assertNoError(err, name + "-Decrypt")
    assertNotEmpty(dedata, name + "-dedata")

    assertEqual(dedata, plaintext, name + "-Equal")
}

func Test_Ciphers(t *testing.T) {
    test_cipher(t, SHA1And3DES, "SHA1And3DES", []byte("hsdfrt5thsdfrt5thsdfrt5t"))
    test_cipher(t, SHA1And2DES, "SHA1And2DES", []byte("hsdfrt5thsdfrt5t"))
    test_cipher(t, SHA1AndRC2_128, "SHA1AndRC2_128", []byte("hsdfrt5thsdfrt5t"))
    test_cipher(t, SHA1AndRC2_40, "SHA1AndRC2_40", []byte("fgtyh"))
    test_cipher(t, SHA1AndRC4_128, "SHA1AndRC4_128", []byte("hsdfrt5thsdfrt5t"))
    test_cipher(t, SHA1AndRC4_40, "SHA1AndRC4_40", []byte("fgtyh"))

    test_cipher(t, MD5AndCAST5, "MD5AndCAST5", []byte("hsdfrt5thsdfrt5t"))
    test_cipher(t, SHAAndTwofish, "SHAAndTwofish", []byte("hsdfrt5thsdfrt5t"))

    test_cipher(t, MD2AndDES, "MD2AndDES", []byte("hsdfrt5t"))
    test_cipher(t, MD2AndRC2_64, "MD2AndRC2_64", []byte("hsdfrt5t"))
    test_cipher(t, MD5AndDES, "MD5AndDES", []byte("hsdfrt5t"))
    test_cipher(t, MD5AndRC2_64, "MD5AndRC2_64", []byte("hsdfrt5t"))
    test_cipher(t, SHA1AndDES, "SHA1AndDES", []byte("hsdfrt5t"))
    test_cipher(t, SHA1AndRC2_64, "SHA1AndRC2_64", []byte("hsdfrt5t"))

}


