package ecsdsa

import (
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var (
    prikey = `
-----BEGIN PRIVATE KEY-----
MHcCAQAwDwYGKPQoAwALBgUrgQQAIQRhMF8CAQEEHHNki0HgNBV6AP+lVTF75L/6
kI+TKkdd0Sr0J7uhPAM6AAT2bjrDo+YFXwoLl9VPJVUaPdtjiLyhXiffk2Zd6I50
aYCkvUyULzB1CbU+lkrxddAAT5yUn0lQcw==
-----END PRIVATE KEY-----
    `

    pubkey = `
-----BEGIN PUBLIC KEY-----
ME0wDwYGKPQoAwALBgUrgQQAIQM6AAT2bjrDo+YFXwoLl9VPJVUaPdtjiLyhXiff
k2Zd6I50aYCkvUyULzB1CbU+lkrxddAAT5yUn0lQcw==
-----END PUBLIC KEY-----
    `

    pubkey2 = `
-----BEGIN PUBLIC KEY-----
ME0wDwYGKPQoAwALBgUrgQQAIQM6AATsLQooA1E1XBILRNr5UiHDp/C8qNmNkVzo
lzqnbiZ8k64s5XJFVsUqb1cS6nWLUOJiRsln5dR4pg==
-----END PUBLIC KEY-----
    `
)

func Test_SignASN1_And_VerifyASN1(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertTrue := cryptobin_test.AssertTrueT(t)

    {
        data := "test-pass"
        objSign := NewECSDSA().
            FromString(data).
            FromPrivateKey([]byte(prikey)).
            SignASN1()

        // t.Errorf("%s \n", objSign.ToBase64String())

        assertNoError(objSign.Error(), "SignASN1")
        assertNotEmpty(objSign.ToBase64String(), "SignASN1")
    }

    {
        data := "test-pass"
        sig := "MEECIQD/8zDT3ihoO3NB8nADqkSES9xlY7Tj3YDB3huUsHxnRAIcPSvqP7BgzcgtaoY3CkErwT1SHICrAF0e4G9W+g=="
        objVerify := NewECSDSA().
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
