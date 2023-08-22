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
    assertError := cryptobin_test.AssertErrorT(t)

    obj := New().
        SetCurve("P256").
        GenerateKey()

    objPriKey := obj.CreateECDHPrivateKey()
    objPubKey := obj.CreateECDHPublicKey()

    assertError(objPriKey.Error(), "ecdhPriKey")
    assertNotEmpty(objPriKey.ToKeyString(), "ecdhPriKey")

    assertError(objPubKey.Error(), "ecdhPubKey")
    assertNotEmpty(objPubKey.ToKeyString(), "ecdhPubKey")
}

func Test_CreateECDHSecretKey(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assert := cryptobin_test.AssertEqualT(t)

    objSecret1 := New().
        FromECDHPrivateKey([]byte(prikey1)).
        FromECDHPublicKey([]byte(pubkey2)).
        CreateSecretKey()
    assertError(objSecret1.Error(), "ecdhCreateSecretKey1")
    assertNotEmpty(objSecret1.ToHexString(), "ecdhCreateSecretKey1")

    objSecret2 := New().
        FromECDHPrivateKey([]byte(prikey2)).
        FromECDHPublicKey([]byte(pubkey1)).
        CreateSecretKey()
    assertError(objSecret2.Error(), "ecdhCreateSecretKey2")
    assertNotEmpty(objSecret2.ToHexString(), "ecdhCreateSecretKey2")

    assert(objSecret1.ToHexString(), objSecret2.ToHexString(), "ecdhCreateSecretKey")
}
