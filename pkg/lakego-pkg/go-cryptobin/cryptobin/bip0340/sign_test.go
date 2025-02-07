package bip0340

import (
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var (
    prikey = `
-----BEGIN PRIVATE KEY-----
MHcCAQAwDwYGKPQoAwAOBgUrgQQAIQRhMF8CAQEEHFGSCJFnOD5T22X6eRTXaj8U
Ou20LRoU3WWq1IKhPAM6AARjo39iPyIBcqR9HR2B62MCVQaolujz78DnIIC6uGFN
ILl2BWUb0iZSoVYch5cB1ztXQnkKw8NIfw==
-----END PRIVATE KEY-----
    `

    pubkey = `
-----BEGIN PUBLIC KEY-----
ME0wDwYGKPQoAwAOBgUrgQQAIQM6AARjo39iPyIBcqR9HR2B62MCVQaolujz78Dn
IIC6uGFNILl2BWUb0iZSoVYch5cB1ztXQnkKw8NIfw==
-----END PUBLIC KEY-----
    `

    pubkey2 = `
-----BEGIN PUBLIC KEY-----
ME0wDwYGKPQoAwAOBgUrgQQAIQM6AASTfd5yqYjuTSTHCWq660ySLg3W9pDCXrXA
F2iehTuwhD2yi4LHFrcB9A1sI7jXajLn+7O9fXhryw==
-----END PUBLIC KEY-----
    `
)

func Test_SignASN1_And_VerifyASN1(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertTrue := cryptobin_test.AssertTrueT(t)

    {
        data := "test-pass"
        objSign := NewBIP0340().
            FromString(data).
            FromPrivateKey([]byte(prikey)).
            SignASN1()

        assertNoError(objSign.Error(), "SignASN1")
        assertNotEmpty(objSign.ToBase64String(), "SignASN1")
    }

    {
        data := "test-pass"
        sig := "MD0CHQD6VkDV6x0ykUqo3Yx2zVzOuo3Cf/39FLyuFuFkAhx4uSeVuI732/P8f7R99qcCgBopXIz57x2ifoiF"
        objVerify := NewBIP0340().
            FromBase64String(sig).
            FromPublicKey([]byte(pubkey)).
            VerifyASN1([]byte(data))

        assertNoError(objVerify.Error(), "VerifyASN1")
        assertTrue(objVerify.ToVerify(), "VerifyASN1")
    }
}

func Test_Sign(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertTrue := cryptobin_test.AssertTrueT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    data := "test-pass"

    // 签名
    objSign := New().
        FromString(data).
        FromPrivateKey([]byte(prikey)).
        Sign()
    signed := objSign.ToBase64String()

    assertNoError(objSign.Error(), "Sign-Sign")
    assertNotEmpty(signed, "Sign-Sign")

    // 验证
    objVerify := New().
        FromBase64String(signed).
        FromPublicKey([]byte(pubkey)).
        Verify([]byte(data))

    assertNoError(objVerify.Error(), "Sign-Verify")
    assertTrue(objVerify.ToVerify(), "Sign-Verify")
}

func Test_SignASN1(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertTrue := cryptobin_test.AssertTrueT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    data := "test-pass"

    // 签名
    objSign := New().
        FromString(data).
        FromPrivateKey([]byte(prikey)).
        SignASN1()
    signed := objSign.ToBase64String()

    assertNoError(objSign.Error(), "SignASN12-Sign")
    assertNotEmpty(signed, "SignASN12-Sign")

    // 验证
    objVerify := New().
        FromBase64String(signed).
        FromPublicKey([]byte(pubkey)).
        VerifyASN1([]byte(data))

    assertNoError(objVerify.Error(), "SignASN12-Verify")
    assertTrue(objVerify.ToVerify(), "SignASN12-Verify")
}

func Test_SignBytes(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertTrue := cryptobin_test.AssertTrueT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    data := "test-pass"

    // 签名
    objSign := New().
        FromString(data).
        FromPrivateKey([]byte(prikey)).
        SignBytes()
    signed := objSign.ToBase64String()

    assertNoError(objSign.Error(), "SignBytes-Sign")
    assertNotEmpty(signed, "SignBytes-Sign")

    // 验证
    objVerify := New().
        FromBase64String(signed).
        FromPublicKey([]byte(pubkey)).
        VerifyBytes([]byte(data))

    assertNoError(objVerify.Error(), "SignBytes-Verify")
    assertTrue(objVerify.ToVerify(), "SignBytes-Verify")
}

func Test_CheckKeyPair(t *testing.T) {
    assertTrue := cryptobin_test.AssertTrueT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    {
        obj := New().
            FromPrivateKey([]byte(prikey)).
            FromPublicKey([]byte(pubkey))

        assertNoError(obj.Error(), "CheckKeyPair")
        assertTrue(obj.CheckKeyPair(), "CheckKeyPair")
    }

    {
        obj := New().
            FromPrivateKey([]byte(prikey)).
            FromPublicKey([]byte(pubkey2))

        assertNoError(obj.Error(), "CheckKeyPair 2")
        assertTrue(!obj.CheckKeyPair(), "CheckKeyPair 2")
    }

}
