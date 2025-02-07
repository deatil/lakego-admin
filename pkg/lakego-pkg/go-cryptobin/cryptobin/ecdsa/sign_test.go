package ecdsa

import (
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var (
    prikey = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZ+qkVZbaR5y/L9XS
bG6z5ky44MZyp/JlUkyAFtZGFgmhRANCAASqS1VTPk6DeYFyeGmd9ZZI6Gtmo75W
7TMKHmGSX/Sv28/M96oakcm/d4nD/MX6BlbGfYu8twqRBNwa61LBV1VF
-----END PRIVATE KEY-----
    `

    pubkey = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqktVUz5Og3mBcnhpnfWWSOhrZqO+
Vu0zCh5hkl/0r9vPzPeqGpHJv3eJw/zF+gZWxn2LvLcKkQTcGutSwVdVRQ==
-----END PUBLIC KEY-----
    `
)

func Test_SignASN1(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    data := "test-pass"
    objSign := NewECDSA().
        FromString(data).
        FromPrivateKey([]byte(prikey)).
        SignASN1()

    assertNoError(objSign.Error(), "SignASN1")
    assertNotEmpty(objSign.ToBase64String(), "SignASN1")
}

func Test_VerifyASN1(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertTrue := cryptobin_test.AssertTrueT(t)

    data := "test-pass"
    sig := "MEUCIBhAZzrS6jM4MfwibzA+j0vBkTEQGvkiDWhx7E6/ePUmAiEAt1uTZXUPGNU9nY8ZS3UxcJCRqwh/G8eeyrAVwM3qen4="
    objVerify := NewECDSA().
        FromBase64String(sig).
        FromPublicKey([]byte(pubkey)).
        VerifyASN1([]byte(data))

    assertNoError(objVerify.Error(), "VerifyASN1")
    assertTrue(objVerify.ToVerify(), "VerifyASN1")
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

func Test_SignASN12(t *testing.T) {
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
