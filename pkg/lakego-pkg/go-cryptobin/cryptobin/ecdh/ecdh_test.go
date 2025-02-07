package ecdh

import (
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var (
    prikey1 = `
-----BEGIN PRIVATE KEY-----
MDgCAQAwEQYFK4EEAQwGCCqGSM49AwEHBCB5afMWLzyIKC/tKa75tK0E15HdCl+m
tXxTL0EDW99TsQ==
-----END PRIVATE KEY-----
    `
    pubkey1 = `
-----BEGIN PUBLIC KEY-----
MFcwEQYFK4EEAQwGCCqGSM49AwEHA0IABDHbqvBSeIxBZkgYU1WKnOjQJiewceMZ
C0y4uVyex3IT9smy8kLDlO9Ups8mRXjsY8MCm5n6quhFx9whn/QG1xs=
-----END PUBLIC KEY-----
    `

    prikey2 = `
-----BEGIN PRIVATE KEY-----
MDgCAQAwEQYFK4EEAQwGCCqGSM49AwEHBCCwBkS+l5MyEqCJhPifr2p5wZhqB40a
FCgqAghW4g/0Fw==
-----END PRIVATE KEY-----
    `
    pubkey2 = `
-----BEGIN PUBLIC KEY-----
MFcwEQYFK4EEAQwGCCqGSM49AwEHA0IABF0F9g+QETASmmSa6JOUzEVeJwhHUTXw
YbGHpDUucpRlNYh0l0cn/cION4/lW64kO/QRYGW+HjmpuMap8Db6DWc=
-----END PUBLIC KEY-----
    `
)

func Test_CreateECDHKey(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    obj := New().
        SetCurve("P256").
        GenerateKey()

    objPriKey := obj.CreateECDHPrivateKey()
    objPubKey := obj.CreateECDHPublicKey()

    assertNoError(objPriKey.Error(), "ecdhPriKey")
    assertNotEmpty(objPriKey.ToKeyString(), "ecdhPriKey")

    assertNoError(objPubKey.Error(), "ecdhPubKey")
    assertNotEmpty(objPubKey.ToKeyString(), "ecdhPubKey")
}

func Test_CreateECDHSecretKey(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assert := cryptobin_test.AssertEqualT(t)

    objSecret1 := New().
        FromECDHPrivateKey([]byte(prikey1)).
        FromECDHPublicKey([]byte(pubkey2)).
        CreateSecretKey()
    assertNoError(objSecret1.Error(), "ecdhCreateSecretKey1")
    assertNotEmpty(objSecret1.ToHexString(), "ecdhCreateSecretKey1")

    objSecret2 := New().
        FromECDHPrivateKey([]byte(prikey2)).
        FromECDHPublicKey([]byte(pubkey1)).
        CreateSecretKey()
    assertNoError(objSecret2.Error(), "ecdhCreateSecretKey2")
    assertNotEmpty(objSecret2.ToHexString(), "ecdhCreateSecretKey2")

    assert(objSecret1.ToHexString(), objSecret2.ToHexString(), "ecdhCreateSecretKey")
}

func Test_CreateKey(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    obj := New().
        SetCurve("P256").
        GenerateKey()

    objPriKey := obj.CreatePrivateKey()
    objEnPriKey := obj.CreatePrivateKeyWithPassword("123", "AES256CBC", "SHA256")
    objPubKey := obj.CreatePublicKey()

    assertNoError(objPriKey.Error(), "CreateKey-ecdhPriKey")
    assertNotEmpty(objPriKey.ToKeyString(), "CreateKey-ecdhPriKey")

    assertNoError(objEnPriKey.Error(), "CreateKey-ecdhEnPriKey")
    assertNotEmpty(objEnPriKey.ToKeyString(), "CreateKey-ecdhEnPriKey")

    assertNoError(objPubKey.Error(), "CreateKey-ecdhPubKey")
    assertNotEmpty(objPubKey.ToKeyString(), "CreateKey-ecdhPubKey")
}

func Test_CreateSecretKey(t *testing.T) {
    names := []string{"P256", "P384", "P256", "X25519"}

    for _, name := range names {
        t.Run(name, func(t *testing.T) {
            test_CreateSecretKey(t, name)
            test_CreateSecretKeyWithPassword(t, name)
        })
    }
}

func test_CreateSecretKey(t *testing.T, name string) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assert := cryptobin_test.AssertEqualT(t)

    obj1 := New().
        SetCurve(name).
        GenerateKey()

    objPriKey1 := obj1.CreatePrivateKey().ToKeyString()
    objPubKey1 := obj1.CreatePublicKey().ToKeyString()

    obj2 := New().
        SetCurve(name).
        GenerateKey()

    objPriKey2 := obj2.CreatePrivateKey().ToKeyString()
    objPubKey2 := obj2.CreatePublicKey().ToKeyString()

    objSecret1 := New().
        FromPrivateKey([]byte(objPriKey1)).
        FromPublicKey([]byte(objPubKey2)).
        CreateSecretKey()
    assertNoError(objSecret1.Error(), "CreateSecretKey-SecretKey")
    assertNotEmpty(objSecret1.ToHexString(), "CreateSecretKey-SecretKey")

    objSecret2 := New().
        FromPrivateKey([]byte(objPriKey2)).
        FromPublicKey([]byte(objPubKey1)).
        CreateSecretKey()
    assertNoError(objSecret2.Error(), "CreateSecretKey-SecretKey2")
    assertNotEmpty(objSecret2.ToHexString(), "CreateSecretKey-SecretKey2")

    assert(objSecret1.ToHexString(), objSecret2.ToHexString(), "CreateSecretKey-Equal")
}

func test_CreateSecretKeyWithPassword(t *testing.T, name string) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assert := cryptobin_test.AssertEqualT(t)

    obj1 := New().
        SetCurve(name).
        GenerateKey()

    objPriKey1 := obj1.CreatePrivateKeyWithPassword("123").ToKeyString()
    objPubKey1 := obj1.CreatePublicKey().ToKeyString()

    obj2 := New().
        SetCurve(name).
        GenerateKey()

    objPriKey2 := obj2.CreatePrivateKey().ToKeyString()
    objPubKey2 := obj2.CreatePublicKey().ToKeyString()

    objSecret1 := New().
        FromPrivateKeyWithPassword([]byte(objPriKey1), "123").
        FromPublicKey([]byte(objPubKey2)).
        CreateSecretKey()
    assertNoError(objSecret1.Error(), "CreateSecretKey-SecretKey")
    assertNotEmpty(objSecret1.ToHexString(), "CreateSecretKey-SecretKey")

    objSecret2 := New().
        FromPrivateKey([]byte(objPriKey2)).
        FromPublicKey([]byte(objPubKey1)).
        CreateSecretKey()
    assertNoError(objSecret2.Error(), "CreateSecretKey-SecretKey2")
    assertNotEmpty(objSecret2.ToHexString(), "CreateSecretKey-SecretKey2")

    assert(objSecret1.ToHexString(), objSecret2.ToHexString(), "CreateSecretKey-Equal")
}
