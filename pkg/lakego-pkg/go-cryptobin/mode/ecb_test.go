package mode

import (
    "testing"
    "crypto/aes"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_ECB(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plo")
    plaintext := []byte("kjinjkijkolkdplo")

    c, err := aes.NewCipher(key)
    assertNoError(err, "Test_ECB")

    mode := NewECBEncrypter(c)
    ciphertext := make([]byte, len(plaintext))
    mode.CryptBlocks(ciphertext, plaintext)

    mode2 := NewECBDecrypter(c)
    plaintext2 := make([]byte, len(ciphertext))
    mode2.CryptBlocks(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "Test_ECB")

    assertEqual(plaintext2, plaintext, "Test_ECB-Equal")
}

func Test_ECB_Check(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    for _, td := range testECBDatas {
        t.Run(td.name, func(t *testing.T) {
            key := td.key
            plaintext := td.pt
            ciphertext := td.ct

            c, err := aes.NewCipher(key)
            assertNoError(err, "Test_ECB_Check")

            mode := NewECBEncrypter(c)
            ciphertext2 := make([]byte, len(plaintext))
            mode.CryptBlocks(ciphertext2, plaintext)

            assertNotEmpty(ciphertext2, "Test_ECB_Check-en")
            assertEqual(ciphertext2, ciphertext, "Test_ECB_Check-En-Equal")

            mode2 := NewECBDecrypter(c)
            plaintext2 := make([]byte, len(ciphertext))
            mode2.CryptBlocks(plaintext2, ciphertext)

            assertNotEmpty(plaintext2, "Test_ECB_Check-de")
            assertEqual(plaintext2, plaintext, "Test_ECB_Check-de-Equal")
        })
    }
}

type testECBData struct {
    name string
    key []byte
    pt []byte
    ct []byte
}

var testECBDatas = []testECBData{
    // aes-128-ecb
    {
        name: "aes-128-ecb",
        key: []byte("1234567890123456"),
        pt: []byte("1234567890123456kjinjkijkolkdplo"),
        ct: fromHex("757ccd0cdc5c90eadbeeecf638dd00005abbde602c9476f8074818ed44ed3eb3"),
    },
    // aes-192-ecb
    {
        name: "aes-192-ecb",
        key: []byte("123456789012345678123456"),
        pt: []byte("1234567890123456kjinjkijkolkdplo"),
        ct: fromHex("485b7c1fef68727c7e7a929a93860eb5014025d768cd33287140a7f65f16780a"),
    },
    // aes-256-ecb
    {
        name: "aes-256-ecb",
        key: []byte("12345678901234561234567890123456"),
        pt: []byte("1234567890123456kjinjkijkolkdplo"),
        ct: fromHex("f38bdd6d129161bf186f2cd4e238f733a607b4ab91bb62d16bdd74022f85da0f"),
    },
}
