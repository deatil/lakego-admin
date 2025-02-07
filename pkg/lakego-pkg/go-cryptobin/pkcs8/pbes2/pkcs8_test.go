package pbes2

import (
    "testing"
    "crypto/rand"
    "encoding/asn1"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_EncryptPKCS8PrivateKey(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    data := "test-data"
    pass := "test-pass"

    block, err := EncryptPKCS8PrivateKey(rand.Reader, "ENCRYPTED PRIVATE KEY", []byte(data), []byte(pass))
    assertNoError(err, "EncryptPKCS8PrivateKey-EN")
    assertNotEmpty(block.Bytes, "EncryptPKCS8PrivateKey-EN")

    deData, err := DecryptPKCS8PrivateKey(block.Bytes, []byte(pass))
    assertNoError(err, "EncryptPKCS8PrivateKey-DE")
    assertNotEmpty(deData, "EncryptPKCS8PrivateKey-DE")

    assertEqual(string(deData), data, "EncryptPKCS8PrivateKey")
}

func Test_prfByOID_fail(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    oidFail := asn1.ObjectIdentifier{1, 222, 643, 777, 12, 13, 5, 1}

    _, err := prfByOID(oidFail)
    if err == nil {
        t.Error("should throw panic")
    }

    check := "go-cryptobin/pkcs8: unsupported hash (OID: 1.222.643.777.12.13.5.1)"
    assertEqual(err.Error(), check, "Test_prfByOID_fail")
}

func Test_EncryptPKCS8PrivateKey2(t *testing.T) {
    test_EncryptPKCS8PrivateKey2(t, "test 1", DefaultOpts)
    test_EncryptPKCS8PrivateKey2(t, "test 2", DefaultSMOpts)

    test_EncryptPKCS8PrivateKey2(t, "test 3", Opts{
        Cipher:  AES256CBC,
        KDFOpts: DefaultPBKDF2Opts,
    })
    test_EncryptPKCS8PrivateKey2(t, "test 4", Opts{
        Cipher:  AES256CBC,
        KDFOpts: DefaultSMPBKDF2Opts,
    })
    test_EncryptPKCS8PrivateKey2(t, "test 5", Opts{
        Cipher:  AES256CBC,
        KDFOpts: DefaultScryptOpts,
    })

    test_EncryptPKCS8PrivateKey2(t, "test 6", Opts{
        Cipher:  AES256CBC,
        KDFOpts: PBKDF2Opts{
            SaltSize:       16,
            IterationCount: 10000,
        },
    })
    test_EncryptPKCS8PrivateKey2(t, "test 7", Opts{
        Cipher:  AES256CBC,
        KDFOpts: PBKDF2Opts{
            SaltSize:       16,
            IterationCount: 10000,
            HMACHash:       SHA256,
        },
    })

    opts21, _ := MakeOpts(Opts{
        Cipher:  AES256CBC,
        KDFOpts: PBKDF2Opts{
            SaltSize:       16,
            IterationCount: 10000,
            HMACHash:       SHA256,
        },
    })
    test_EncryptPKCS8PrivateKey2(t, "test 8", opts21)

    opts22, _ := MakeOpts(AES256CBC)
    test_EncryptPKCS8PrivateKey2(t, "test 9", opts22)

    opts23, _ := MakeOpts(AES256CBC, SHA256)
    test_EncryptPKCS8PrivateKey2(t, "test 10", opts23)

    opts23_1, _ := MakeOpts(AES256CBC, "SHA256")
    test_EncryptPKCS8PrivateKey2(t, "test 10-1", opts23_1)

    opts24, _ := MakeOpts("AES256CBC")
    test_EncryptPKCS8PrivateKey2(t, "test 11", opts24)

    opts25, _ := MakeOpts("AES256CBC", "SHA256")
    test_EncryptPKCS8PrivateKey2(t, "test 12", opts25)

    opts26, _ := MakeOpts("AES256CBC", SHA256)
    test_EncryptPKCS8PrivateKey2(t, "test 13", opts26)

}

func test_EncryptPKCS8PrivateKey2(t *testing.T, name string, opts Opts) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    t.Run(name, func(t *testing.T) {
        data := "test-data"
        pass := "test-pass"

        block, err := EncryptPKCS8PrivateKey(rand.Reader, "ENCRYPTED PRIVATE KEY", []byte(data), []byte(pass), opts)
        assertNoError(err, "test_EncryptPKCS8PrivateKey2-EN")
        assertNotEmpty(block.Bytes, "test_EncryptPKCS8PrivateKey2-EN")

        deData, err := DecryptPKCS8PrivateKey(block.Bytes, []byte(pass))
        assertNoError(err, "test_EncryptPKCS8PrivateKey2-DE")
        assertNotEmpty(deData, "test_EncryptPKCS8PrivateKey2-DE")

        assertEqual(string(deData), data, "test_EncryptPKCS8PrivateKey2")
    })

}
