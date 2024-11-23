package bign

import (
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var (
    prikey = `
-----BEGIN PRIVATE KEY-----
MIGMAgEAMBgGCipwAAIAImUtAgEGCipwAAIAImUtAwEEbTBrAgEBBCDExu0qBLnd
FDEfEXc2Nft72QD2J2HYRr3EU4x0QM1BBqFEA0IABG5NUyNKNtnu+/7/7ODqSOtG
7oCtUEuRqVgvnireGA69uO5KS/RgAsf9ERVDZJHxKtwOYIXS2+/seXz/0sX+NPU=
-----END PRIVATE KEY-----
    `

    pubkey = `
-----BEGIN PUBLIC KEY-----
MF4wGAYKKnAAAgAiZS0CAQYKKnAAAgAiZS0DAQNCAARuTVMjSjbZ7vv+/+zg6kjr
Ru6ArVBLkalYL54q3hgOvbjuSkv0YALH/REVQ2SR8SrcDmCF0tvv7Hl8/9LF/jT1
-----END PUBLIC KEY-----
    `

    pubkey2 = `
-----BEGIN PUBLIC KEY-----
MFEwEwYKKnAAAgAiZS0CAQYFK4EEACEDOgAEzcoYnYchmsKJIu3IIFF8X6L91Vv3
M2Nie29mugemzh6T00lM1bDeD1PqBs8weCpFFv20s62c3CQ=
-----END PUBLIC KEY-----
    `
)

func Test_SignASN1_And_VerifyASN1(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertBool := cryptobin_test.AssertBoolT(t)

    data := "test-pass"
    adata := []byte{
        0x00, 0x0b, 0x00, 0x00,
        0x06, 0x09, 0x2A, 0x70, 0x00, 0x02, 0x00, 0x22, 0x65, 0x1F, 0x51,
    }

    {
        objSign := NewBign().
            FromString(data).
            FromPrivateKey([]byte(prikey)).
            WithAdata(adata).
            SignASN1()

        assertError(objSign.Error(), "SignASN1")
        assertNotEmpty(objSign.ToBase64String(), "SignASN1")
    }

    {
        sig := "MDMCD2xLWwgWCM9JjiU3+dZxDAIgGBtQI9XH1aGuOFJztX+ImtyK3zoXbHTt/vBoNMr2ug0="
        objVerify := NewBign().
            FromBase64String(sig).
            FromPublicKey([]byte(pubkey)).
            WithAdata(adata).
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
    adata := []byte{
        0x00, 0x0b, 0x00, 0x00,
        0x06, 0x09, 0x2A, 0x70, 0x00, 0x02, 0x00, 0x22, 0x65, 0x1F, 0x51,
    }

    // 签名
    objSign := New().
        FromString(data).
        FromPrivateKey([]byte(prikey)).
        WithAdata(adata).
        Sign()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "Sign-Sign")
    assertNotEmpty(signed, "Sign-Sign")

    // 验证
    objVerify := New().
        FromBase64String(signed).
        FromPublicKey([]byte(pubkey)).
        WithAdata(adata).
        Verify([]byte(data))

    assertError(objVerify.Error(), "Sign-Verify")
    assertBool(objVerify.ToVerify(), "Sign-Verify")
}

func Test_SignASN1(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"
    adata := []byte{
        0x00, 0x0b, 0x00, 0x00,
        0x06, 0x09, 0x2A, 0x70, 0x00, 0x02, 0x00, 0x22, 0x65, 0x1F, 0x51,
    }

    // 签名
    objSign := New().
        FromString(data).
        FromPrivateKey([]byte(prikey)).
        WithAdata(adata).
        SignASN1()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "SignASN12-Sign")
    assertNotEmpty(signed, "SignASN12-Sign")

    // 验证
    objVerify := New().
        FromBase64String(signed).
        FromPublicKey([]byte(pubkey)).
        WithAdata(adata).
        VerifyASN1([]byte(data))

    assertError(objVerify.Error(), "SignASN12-Verify")
    assertBool(objVerify.ToVerify(), "SignASN12-Verify")
}

func Test_SignBytes(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"
    adata := []byte{
        0x00, 0x0b, 0x00, 0x00,
        0x06, 0x09, 0x2A, 0x70, 0x00, 0x02, 0x00, 0x22, 0x65, 0x1F, 0x51,
    }

    // 签名
    objSign := New().
        FromString(data).
        FromPrivateKey([]byte(prikey)).
        WithAdata(adata).
        SignBytes()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "SignBytes-Sign")
    assertNotEmpty(signed, "SignBytes-Sign")

    // 验证
    objVerify := New().
        FromBase64String(signed).
        FromPublicKey([]byte(pubkey)).
        WithAdata(adata).
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
