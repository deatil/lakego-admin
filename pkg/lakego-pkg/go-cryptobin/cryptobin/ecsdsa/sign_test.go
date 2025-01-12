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
    assertError := cryptobin_test.AssertErrorT(t)
    assertBool := cryptobin_test.AssertBoolT(t)

    {
        data := "test-pass"
        objSign := NewECSDSA().
            FromString(data).
            FromPrivateKey([]byte(prikey)).
            SignASN1()

        // t.Errorf("%s \n", objSign.ToBase64String())

        assertError(objSign.Error(), "SignASN1")
        assertNotEmpty(objSign.ToBase64String(), "SignASN1")
    }

    {
        data := "test-pass"
        sig := "MEECIQD/8zDT3ihoO3NB8nADqkSES9xlY7Tj3YDB3huUsHxnRAIcPSvqP7BgzcgtaoY3CkErwT1SHICrAF0e4G9W+g=="
        objVerify := NewECSDSA().
            FromBase64String(sig).
            FromPublicKey([]byte(pubkey)).
            VerifyASN1([]byte(data))

        assertError(objVerify.Error(), "VerifyASN1")
        assertBool(objVerify.ToVerify(), "VerifyASN1")
    }
}

func Test_Sign(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"

    // 签名
    objSign := New().
        FromString(data).
        FromPrivateKey([]byte(prikey)).
        Sign()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "Sign-Sign")
    assertNotEmpty(signed, "Sign-Sign")

    // 验证
    objVerify := New().
        FromBase64String(signed).
        FromPublicKey([]byte(pubkey)).
        Verify([]byte(data))

    assertError(objVerify.Error(), "Sign-Verify")
    assertBool(objVerify.ToVerify(), "Sign-Verify")
}

func Test_SignASN1(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"

    // 签名
    objSign := New().
        FromString(data).
        FromPrivateKey([]byte(prikey)).
        SignASN1()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "SignASN12-Sign")
    assertNotEmpty(signed, "SignASN12-Sign")

    // 验证
    objVerify := New().
        FromBase64String(signed).
        FromPublicKey([]byte(pubkey)).
        VerifyASN1([]byte(data))

    assertError(objVerify.Error(), "SignASN12-Verify")
    assertBool(objVerify.ToVerify(), "SignASN12-Verify")
}

func Test_SignBytes(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"

    // 签名
    objSign := New().
        FromString(data).
        FromPrivateKey([]byte(prikey)).
        SignBytes()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "SignBytes-Sign")
    assertNotEmpty(signed, "SignBytes-Sign")

    // 验证
    objVerify := New().
        FromBase64String(signed).
        FromPublicKey([]byte(pubkey)).
        VerifyBytes([]byte(data))

    assertError(objVerify.Error(), "SignBytes-Verify")
    assertBool(objVerify.ToVerify(), "SignBytes-Verify")
}

func Test_CheckKeyPair(t *testing.T) {
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    {
        obj := New().
            FromPrivateKey([]byte(prikey)).
            FromPublicKey([]byte(pubkey))

        assertError(obj.Error(), "CheckKeyPair")
        assertBool(obj.CheckKeyPair(), "CheckKeyPair")
    }

    {
        obj := New().
            FromPrivateKey([]byte(prikey)).
            FromPublicKey([]byte(pubkey2))

        assertError(obj.Error(), "CheckKeyPair 2")
        assertBool(!obj.CheckKeyPair(), "CheckKeyPair 2")
    }

}
