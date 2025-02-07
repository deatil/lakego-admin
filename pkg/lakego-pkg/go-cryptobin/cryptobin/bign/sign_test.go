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
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertTrue := cryptobin_test.AssertTrueT(t)

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

        assertNoError(objSign.Error(), "SignASN1")
        assertNotEmpty(objSign.ToBase64String(), "SignASN1")
    }

    {
        sig := "MDMCD2xLWwgWCM9JjiU3+dZxDAIgGBtQI9XH1aGuOFJztX+ImtyK3zoXbHTt/vBoNMr2ug0="
        objVerify := NewBign().
            FromBase64String(sig).
            FromPublicKey([]byte(pubkey)).
            WithAdata(adata).
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

    assertNoError(objSign.Error(), "Sign-Sign")
    assertNotEmpty(signed, "Sign-Sign")

    // 验证
    objVerify := New().
        FromBase64String(signed).
        FromPublicKey([]byte(pubkey)).
        WithAdata(adata).
        Verify([]byte(data))

    assertNoError(objVerify.Error(), "Sign-Verify")
    assertTrue(objVerify.ToVerify(), "Sign-Verify")
}

func Test_SignASN1(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertTrue := cryptobin_test.AssertTrueT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

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

    assertNoError(objSign.Error(), "SignASN12-Sign")
    assertNotEmpty(signed, "SignASN12-Sign")

    // 验证
    objVerify := New().
        FromBase64String(signed).
        FromPublicKey([]byte(pubkey)).
        WithAdata(adata).
        VerifyASN1([]byte(data))

    assertNoError(objVerify.Error(), "SignASN12-Verify")
    assertTrue(objVerify.ToVerify(), "SignASN12-Verify")
}

func Test_SignBytes(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertTrue := cryptobin_test.AssertTrueT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

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

    assertNoError(objSign.Error(), "SignBytes-Sign")
    assertNotEmpty(signed, "SignBytes-Sign")

    // 验证
    objVerify := New().
        FromBase64String(signed).
        FromPublicKey([]byte(pubkey)).
        WithAdata(adata).
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
