package ecdh

import (
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_CreateKey(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    obj := New().GenerateKey()

    objPriKey := obj.CreatePrivateKey()
    objEnPriKey := obj.CreatePrivateKeyWithPassword("123", "AES256CBC", "SHA256")
    objPubKey := obj.CreatePublicKey()

    assertNoError(objPriKey.Error(), "CreateKey-objPriKey")
    assertNotEmpty(objPriKey.ToKeyString(), "CreateKey-objPriKey")

    assertNoError(objEnPriKey.Error(), "CreateKey-objEnPriKey")
    assertNotEmpty(objEnPriKey.ToKeyString(), "CreateKey-objEnPriKey")

    assertNoError(objPubKey.Error(), "CreateKey-objPubKey")
    assertNotEmpty(objPubKey.ToKeyString(), "CreateKey-objPubKey")
}

func Test_CreateSecretKey(t *testing.T) {
    test_CreateSecretKey(t)
    test_CreateSecretKeyWithPassword(t)
}

func test_CreateSecretKey(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assert := cryptobin_test.AssertEqualT(t)

    obj1 := New().GenerateKey()

    objPriKey1 := obj1.CreatePrivateKey().ToKeyString()
    objPubKey1 := obj1.CreatePublicKey().ToKeyString()

    obj2 := New().GenerateKey()

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

func test_CreateSecretKeyWithPassword(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assert := cryptobin_test.AssertEqualT(t)

    obj1 := New().GenerateKey()

    objPriKey1 := obj1.CreatePrivateKeyWithPassword("123").ToKeyString()
    objPubKey1 := obj1.CreatePublicKey().ToKeyString()

    obj2 := New().GenerateKey()

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
