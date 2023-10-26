package ed448

import (
    "fmt"
    "crypto"
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var (
    testPrikey = `
-----BEGIN PRIVATE KEY-----
MEcCAQAwBQYDK2VxBDsEOR55/vxbgbFLqR/VoNp9XiIzV7rlEryjy//7n+oKXCS/
2f518iVc1TOQAnfildfuEjD10Y+4DNc7rw==
-----END PRIVATE KEY-----
    `
    testPubkey = `-----BEGIN PUBLIC KEY-----
MEMwBQYDK2VxAzoA99wpDUrUqypB0IInxULQ+iL1jkJYQTS5Kgta48LxBNCyuoZU
j76wR72a3vP4CikpNlHFeij/s7kA
-----END PUBLIC KEY-----
`

    testPrikeyEn = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIGzMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBCbL/KwfBrFjJTiez7i
WYZuAgInEDAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQSx3aAgywMbqIQjDr
Ir6CTQRQs6wsvGy4WDkZPdHPMvfKgxRoW6wG8NlJtFhqNRp1LI5V59F0+YvFpaJH
Mcvh5HNCYcmi+Q38RAkT0uQLyzeJ9QLk36DNR3nJMYibGyGOpAE=
-----END ENCRYPTED PRIVATE KEY-----
    `
    testPubkeyEn = `
-----BEGIN PUBLIC KEY-----
MEMwBQYDK2VxAzoAYRO+ws1nXb89sYPEeSmxFIU8Qwz04ZM8tNRVfvDuiCMWWILR
9x1DVJAAGM8IVZQek6uHREFT17MA
-----END PUBLIC KEY-----
    `
)

func testED448Sign(t *testing.T, opts *Options) {
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    data := []byte("test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass3333333333333333333333333333333333333333333333333333test-pa2222222222222222222222222222222222222222222sstest-passt111111111111111111111111111111111est-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passt-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass")

    hashed := FromBytes(data).
        FromPrivateKey([]byte(testPrikey)).
        WithOptions(opts).
        Sign()
    hashedData := hashed.ToBase64String()

    assertError(hashed.Error(), "ED448Sign-Sign")
    assertNotEmpty(hashedData, "ED448Sign-Sign")

    // ===

    dehashed := FromBase64String(hashedData).
        FromPublicKey([]byte(testPubkey)).
        WithOptions(opts).
        Verify(data)
    dehashedVerify := dehashed.ToVerify()

    assertError(dehashed.Error(), "ED448Sign-Verify")
    assertBool(dehashedVerify, "ED448Sign-Verify")
}

func Test_ED448Sign(t *testing.T) {
    ctx := "ase3ertygfa1"

    optses := []*Options{
        &Options{
            Hash:    crypto.Hash(0),
            Context: ctx,
            Scheme:  SchemeED448,
        },
        &Options{
            Hash:    crypto.Hash(0),
            Context: ctx,
            Scheme:  SchemeED448Ph,
        },
        &Options{
            Hash:    crypto.Hash(0),
            Context: "",
            Scheme:  SchemeED448,
        },
        &Options{
            Hash:    crypto.Hash(0),
            Context: "",
            Scheme:  SchemeED448Ph,
        },
    }

    i := 1
    for _, opts := range optses {
        t.Run(fmt.Sprintf("ED448 index %d", i), func(t *testing.T) {
            testED448Sign(t, opts)
        })

        i += 1
    }
}

func Test_CreateKey(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    obj := New().GenerateKey()

    objPriKey := obj.CreatePrivateKey()
    priKey := objPriKey.ToKeyString()

    assertError(objPriKey.Error(), "CreateKey-priKey")
    assertNotEmpty(priKey, "CreateKey-priKey")

    objPriKeyEn := obj.CreatePrivateKeyWithPassword("123", "AES256CBC", "SHA256")
    priKeyEn := objPriKeyEn.ToKeyString()

    assertError(objPriKeyEn.Error(), "CreateKey-priKeyEn")
    assertNotEmpty(priKeyEn, "CreateKey-priKeyEn")

    objPubKey := obj.CreatePublicKey()
    pubKey := objPubKey.ToKeyString()

    assertError(objPubKey.Error(), "CreateKey-pubKey")
    assertNotEmpty(pubKey, "CreateKey-pubKey")
}

func Test_CheckKeyPair(t *testing.T) {
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    check := New().
        FromPublicKey([]byte(testPubkey)).
        FromPrivateKey([]byte(testPrikey))
    checkData := check.CheckKeyPair()

    assertError(check.Error(), "CheckKeyPair")
    assertBool(checkData, "CheckKeyPair")

    // ==========

    checkEn := New().
        FromPublicKey([]byte(testPubkeyEn)).
        FromPrivateKeyWithPassword([]byte(testPrikeyEn), "123")
    checkDataEn := checkEn.CheckKeyPair()

    assertError(checkEn.Error(), "CheckKeyPair-EnPri")
    assertBool(checkDataEn, "CheckKeyPair-EnPri")
}

func Test_MakePublicKey(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    ed := New().FromPrivateKey([]byte(testPrikey))
    newPubkey := ed.MakePublicKey().
        CreatePublicKey().
        ToKeyString()

    assertError(ed.Error(), "MakePublicKey")
    assertEqual(newPubkey, testPubkey, "MakePublicKey")
}
