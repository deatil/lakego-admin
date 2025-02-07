package ecgdsa

import (
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var (
    prikey = `
-----BEGIN PRIVATE KEY-----
MIGIAgEAMBQGCCskAwMCBQIBBggqhkjOPQMBBwRtMGsCAQEEIMoNOrmfmMEIFn2L
UH4RYaxzgpv09S0+qMKwJTiQ5qTloUQDQgAEpXIRKs3qaQYe2hkATIzhTc9O7/sY
0OjWcvYePRg+rHn74YFFaYWoNgantg5ERJzNNQn6y3s+ZzQEI5IWlOEJZQ==
-----END PRIVATE KEY-----
    `

    pubkey = `
-----BEGIN PUBLIC KEY-----
MFowFAYIKyQDAwIFAgEGCCqGSM49AwEHA0IABKVyESrN6mkGHtoZAEyM4U3PTu/7
GNDo1nL2Hj0YPqx5++GBRWmFqDYGp7YORESczTUJ+st7Pmc0BCOSFpThCWU=
-----END PUBLIC KEY-----
    `

    pubkey2 = `
-----BEGIN PUBLIC KEY-----
ME8wEQYIKyQDAwIFAgEGBSuBBAAhAzoABILd0VpnGfuYjhu0rBD6HF6F6YYmKJTe
AO3FivH8Fzlf3PpdkYCPs2mxQozfNYcwpIvfcCAI3dF4
-----END PUBLIC KEY-----
    `
)

func Test_SignASN1_And_VerifyASN1(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertTrue := cryptobin_test.AssertTrueT(t)

    {
        data := "test-pass"
        objSign := NewECGDSA().
            FromString(data).
            FromPrivateKey([]byte(prikey)).
            SignASN1()

        assertNoError(objSign.Error(), "SignASN1")
        assertNotEmpty(objSign.ToBase64String(), "SignASN1")
    }

    {
        data := "test-pass"
        sig := "MEUCIQDeA0iRFDtzAb4ZuAjLDRZdyfQ0rOMZa/thVdzQLkqJLAIgcQ9iqX3UvENp+6c9sdnnh0m2g63EDPEN7tJthxYCAtQ="
        objVerify := NewECGDSA().
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
