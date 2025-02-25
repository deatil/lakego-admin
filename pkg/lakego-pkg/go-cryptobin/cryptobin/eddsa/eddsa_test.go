package eddsa

import (
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_CreateKey(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    obj := New().GenerateKey()

    objPriKey := obj.CreatePrivateKey()
    priKey := objPriKey.ToKeyString()

    assertNoError(objPriKey.Error(), "CreateKey-priKey")
    assertNotEmpty(priKey, "CreateKey-priKey")

    objPriKeyEn := obj.CreatePrivateKeyWithPassword("123", "AES256CBC", "SHA256")
    priKeyEn := objPriKeyEn.ToKeyString()

    assertNoError(objPriKeyEn.Error(), "CreateKey-priKeyEn")
    assertNotEmpty(priKeyEn, "CreateKey-priKeyEn")

    objPubKey := obj.CreatePublicKey()
    pubKey := objPubKey.ToKeyString()

    assertNoError(objPubKey.Error(), "CreateKey-pubKey")
    assertNotEmpty(pubKey, "CreateKey-pubKey")
}

func Test_CheckKeyPair(t *testing.T) {
    assertTrue := cryptobin_test.AssertTrueT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    check := New().
        FromPublicKey([]byte(testPubkey)).
        FromPrivateKey([]byte(testPrikey))
    checkData := check.CheckKeyPair()

    assertNoError(check.Error(), "CheckKeyPair")
    assertTrue(checkData, "CheckKeyPair")

    // ==========

    checkEn := New().
        FromPublicKey([]byte(testPubkeyEn)).
        FromPrivateKeyWithPassword([]byte(testPrikeyEn), "123")
    checkDataEn := checkEn.CheckKeyPair()

    assertNoError(checkEn.Error(), "CheckKeyPair-EnPri")
    assertTrue(checkDataEn, "CheckKeyPair-EnPri")
}

func Test_MakePublicKey(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    ed := New().FromPrivateKey([]byte(testPrikey))
    newPubkey := ed.MakePublicKey().
        CreatePublicKey().
        ToKeyString()

    assertNoError(ed.Error(), "MakePublicKey")
    assertEqual(newPubkey, testPubkey, "MakePublicKey")
}

func Test_CheckKeyString(t *testing.T) {
    ed := New().GenerateKey()

    priString := ed.GetPrivateKeyString()
    pubString := ed.GetPublicKeyString()

    cryptobin_test.NotEmpty(t, priString)
    cryptobin_test.NotEmpty(t, pubString)

    pri := New().
            FromPrivateKeyString(priString).
            GetPrivateKey()
    pub := New().
            FromPublicKeyString(pubString).
            GetPublicKey()

    cryptobin_test.Equal(t, ed.GetPrivateKey(), pri)
    cryptobin_test.Equal(t, ed.GetPublicKey(), pub)
}
