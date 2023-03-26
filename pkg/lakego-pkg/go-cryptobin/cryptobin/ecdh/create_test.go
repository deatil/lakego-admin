package ecdh

import (
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var (
    prikey1 = `
-----BEGIN PRIVATE KEY-----
MDUCAQAwDgYFK4EEAQwEBVAtMjU2BCBIRVjkths2BfwuSGn6Iq68uNsFC2PjsjZZ
RqngHoHQVA==
-----END PRIVATE KEY-----
    `
    pubkey1 = `
-----BEGIN PUBLIC KEY-----
MFQwDgYFK4EEAQwEBVAtMjU2A0IABFamGjiPRBwyBFH/fkzg2HZSYuaz1lVQys/P
mFyITpZQitmsDy5LxAfGz3dL0OlyVWh4oDYM8Hh9qjVYGiI6wGU=
-----END PUBLIC KEY-----
    `

    prikey2 = `
-----BEGIN PRIVATE KEY-----
MDUCAQAwDgYFK4EEAQwEBVAtMjU2BCCex3Jxff1fiYK0aHjhC/EqsjTyqkZ7TrU7
thllPJaFLw==
-----END PRIVATE KEY-----
    `
    pubkey2 = `
-----BEGIN PUBLIC KEY-----
MFQwDgYFK4EEAQwEBVAtMjU2A0IABB2mTn2/D2xzqLdhWg8vAQ8d8iCBDQmz4mTR
JI+OlWjOpOq33qAdLLv0R9zUzcMcQvQQ4pe3RKOEs7rZq1/rq+w=
-----END PUBLIC KEY-----
    `
)

func Test_CreateKey(t *testing.T) {
    assertEmpty := cryptobin_test.AssertEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    obj := New().
        SetCurve("P256").
        GenerateKey()

    objPriKey := obj.CreatePrivateKey()
    objPubKey := obj.CreatePublicKey()

    assertError(objPriKey.Error(), "ecdhPriKey")
    assertEmpty(objPriKey.ToKeyString(), "ecdhPriKey")

    assertError(objPubKey.Error(), "ecdhPubKey")
    assertEmpty(objPubKey.ToKeyString(), "ecdhPubKey")
}

func Test_CreateSecretKey(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEmpty := cryptobin_test.AssertEmptyT(t)
    assert := cryptobin_test.AssertT(t)

    objSecret1 := New().
        FromPrivateKey([]byte(prikey1)).
        FromPublicKey([]byte(pubkey2)).
        CreateSecretKey()
    assertError(objSecret1.Error(), "ecdhCreateSecretKey1")
    assertEmpty(objSecret1.ToHexString(), "ecdhCreateSecretKey1")

    objSecret2 := New().
        FromPrivateKey([]byte(prikey2)).
        FromPublicKey([]byte(pubkey1)).
        CreateSecretKey()
    assertError(objSecret2.Error(), "ecdhCreateSecretKey2")
    assertEmpty(objSecret2.ToHexString(), "ecdhCreateSecretKey2")

    assert(objSecret1.ToHexString(), objSecret2.ToHexString(), "ecdhCreateSecretKey")
}
