package pbes2

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
    test_cipher(t, DESCBC, "DESCBC", []byte("ssdfrt5t"))
    test_cipher(t, DESEDE3CBC, "DESEDE3CBC", []byte("ssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, RC2CBC, "RC2CBC", []byte("ssdfrt5tssdfrt5t"))
    test_cipher(t, RC5CBC, "RC5CBC", []byte("ssdfrt5tssdfrt5t"))

    test_cipher(t, AES128CBC, "AES128CBC", []byte("ssdfrt5tssdfrt5t"))
    test_cipher(t, AES128OFB, "AES128OFB", []byte("ssdfrt5tssdfrt5t"))
    test_cipher(t, AES128CFB, "AES128CFB", []byte("ssdfrt5tssdfrt5t"))
    test_cipher(t, AES128GCM, "AES128GCM", []byte("ssdfrt5tssdfrt5t"))
    test_cipher(t, AES128GCMIv, "AES128GCMIv", []byte("ssdfrt5tssdfrt5t"))
    test_cipher(t, AES128CCM, "AES128CCM", []byte("ssdfrt5tssdfrt5t"))
    test_cipher(t, AES128CCMIv, "AES128CCMIv", []byte("ssdfrt5tssdfrt5t"))

    test_cipher(t, AES192CBC, "AES192CBC", []byte("ssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, AES192OFB, "AES192OFB", []byte("ssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, AES192CFB, "AES192CFB", []byte("ssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, AES192GCM, "AES192GCM", []byte("ssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, AES192GCMIv, "AES192GCMIv", []byte("ssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, AES192CCM, "AES192CCM", []byte("ssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, AES192CCMIv, "AES192CCMIv", []byte("ssdfrt5tssdfrt5tssdfrt5t"))

    test_cipher(t, AES256CBC, "AES256CBC", []byte("ghiolkjmssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, AES256OFB, "AES256OFB", []byte("ghiolkjmssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, AES256CFB, "AES256CFB", []byte("ghiolkjmssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, AES256GCM, "AES256GCM", []byte("ghiolkjmssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, AES256GCMIv, "AES256GCMIv", []byte("ghiolkjmssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, AES256CCM, "AES256CCM", []byte("ghiolkjmssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, AES256CCMIv, "AES256CCMIv", []byte("ghiolkjmssdfrt5tssdfrt5tssdfrt5t"))

    test_cipher(t, SM4Cipher, "SM4Cipher", []byte("ghdfrt5tssdfrt5t"))
    test_cipher(t, SM4CBC, "SM4CBC", []byte("ghdfrt5tssdfrt5t"))
    test_cipher(t, SM4OFB, "SM4OFB", []byte("ghdfrt5tssdfrt5t"))
    test_cipher(t, SM4CFB, "SM4CFB", []byte("ghdfrt5tssdfrt5t"))
    test_cipher(t, SM4CFB1, "SM4CFB1", []byte("ghdfrt5tssdfrt5t"))
    test_cipher(t, SM4CFB8, "SM4CFB8", []byte("ghdfrt5tssdfrt5t"))
    test_cipher(t, SM4GCM, "SM4GCM", []byte("ghdfrt5tssdfrt5t"))
    test_cipher(t, SM4GCMIv, "SM4GCMIv", []byte("ghdfrt5tssdfrt5t"))
    test_cipher(t, SM4CCM, "SM4CCM", []byte("ghdfrt5tssdfrt5t"))
    test_cipher(t, SM4CCMIv, "SM4CCMIv", []byte("ghdfrt5tssdfrt5t"))

    test_cipher(t, GostCipher, "GostCipher", []byte("ghdfrt5tssdfrt5tghdfrt5tssdfrt5t"))

    test_cipher(t, ARIA128ECB, "ARIA128ECB", []byte("ssdfrt5tssdfrt5t"))
    test_cipher(t, ARIA128CBC, "ARIA128CBC", []byte("ssdfrt5tssdfrt5t"))
    test_cipher(t, ARIA128CFB, "ARIA128CFB", []byte("ssdfrt5tssdfrt5t"))
    test_cipher(t, ARIA128OFB, "ARIA128OFB", []byte("ssdfrt5tssdfrt5t"))
    test_cipher(t, ARIA128CTR, "ARIA128CTR", []byte("ssdfrt5tssdfrt5t"))
    test_cipher(t, ARIA128GCM, "ARIA128GCM", []byte("ssdfrt5tssdfrt5t"))
    test_cipher(t, ARIA128CCM, "ARIA128CCM", []byte("ssdfrt5tssdfrt5t"))

    test_cipher(t, ARIA192ECB, "ARIA192ECB", []byte("ssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, ARIA192CBC, "ARIA192CBC", []byte("ssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, ARIA192CFB, "ARIA192CFB", []byte("ssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, ARIA192OFB, "ARIA192OFB", []byte("ssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, ARIA192CTR, "ARIA192CTR", []byte("ssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, ARIA192GCM, "ARIA192GCM", []byte("ssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, ARIA192CCM, "ARIA192CCM", []byte("ssdfrt5tssdfrt5tssdfrt5t"))

    test_cipher(t, ARIA256ECB, "ARIA256ECB", []byte("ghiolkjmssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, ARIA256CBC, "ARIA256CBC", []byte("ghiolkjmssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, ARIA256CFB, "ARIA256CFB", []byte("ghiolkjmssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, ARIA256OFB, "ARIA256OFB", []byte("ghiolkjmssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, ARIA256CTR, "ARIA256CTR", []byte("ghiolkjmssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, ARIA256GCM, "ARIA256GCM", []byte("ghiolkjmssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, ARIA256CCM, "ARIA256CCM", []byte("ghiolkjmssdfrt5tssdfrt5tssdfrt5t"))

    test_cipher(t, Serpent128ECB, "Serpent128ECB", []byte("ssdfrt5tssdfrt5t"))
    test_cipher(t, Serpent128CBC, "Serpent128CBC", []byte("ssdfrt5tssdfrt5t"))
    test_cipher(t, Serpent128OFB, "Serpent128OFB", []byte("ssdfrt5tssdfrt5t"))
    test_cipher(t, Serpent128CFB, "Serpent128CFB", []byte("ssdfrt5tssdfrt5t"))

    test_cipher(t, Serpent192ECB, "Serpent192ECB", []byte("ssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, Serpent192CBC, "Serpent192CBC", []byte("ssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, Serpent192OFB, "Serpent192OFB", []byte("ssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, Serpent192CFB, "Serpent192CFB", []byte("ssdfrt5tssdfrt5tssdfrt5t"))

    test_cipher(t, Serpent256ECB, "Serpent256ECB", []byte("ghiolkjmssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, Serpent256CBC, "Serpent256CBC", []byte("ghiolkjmssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, Serpent256OFB, "Serpent256OFB", []byte("ghiolkjmssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, Serpent256CFB, "Serpent256CFB", []byte("ghiolkjmssdfrt5tssdfrt5tssdfrt5t"))

    // Seed
    test_cipher(t, SeedECB, "SeedECB", []byte("ssdfrt5tssdfrt5t"))
    test_cipher(t, SeedCBC, "SeedCBC", []byte("ssdfrt5tssdfrt5t"))
    test_cipher(t, SeedOFB, "SeedOFB", []byte("ssdfrt5tssdfrt5t"))
    test_cipher(t, SeedCFB, "SeedCFB", []byte("ssdfrt5tssdfrt5t"))

    test_cipher(t, Seed256ECB, "Seed256ECB", []byte("ghiolkjmssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, Seed256CBC, "Seed256CBC", []byte("ghiolkjmssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, Seed256OFB, "Seed256OFB", []byte("ghiolkjmssdfrt5tssdfrt5tssdfrt5t"))
    test_cipher(t, Seed256CFB, "Seed256CFB", []byte("ghiolkjmssdfrt5tssdfrt5tssdfrt5t"))
}


