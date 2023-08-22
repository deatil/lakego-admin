package eddsa

import (
    "crypto"
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var (
    testPrikey = `
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIOXADd7nzUp08BdkP9n9h/sFrjsi0xcK3gm8tHKBHCvK
-----END PRIVATE KEY-----
    `
    testPubkey = `
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA1NkD+0884Ol0mqyreYT+I6AA2y/rKDS+eIueB/vxMVc=
-----END PUBLIC KEY-----
    `
)

func useEdDSASign(t *testing.T, opts *Options) {
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    data := []byte("test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass3333333333333333333333333333333333333333333333333333test-pa2222222222222222222222222222222222222222222sstest-passt111111111111111111111111111111111est-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passt-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass")

    hashed := FromBytes(data).
        FromPrivateKey([]byte(testPrikey)).
        WithOptions(opts).
        Sign()
    hashedData := hashed.ToBase64String()

    assertError(hashed.Error(), "EdDSASign-Sign")
    assertNotEmpty(hashedData, "EdDSASign-Sign")

    // ===

    dehashed := FromBase64String(hashedData).
        FromPublicKey([]byte(testPubkey)).
        WithOptions(opts).
        Verify(data)
    dehashedVerify := dehashed.ToVerify()

    assertError(dehashed.Error(), "EdDSASign-Verify")
    assertBool(dehashedVerify, "EdDSASign-Verify")
}

func Test_EdDSASign(t *testing.T) {
    ctx := "ase3ertygfa1"

    optses := []*Options{
        &Options{
            Hash:    crypto.SHA512,
            Context: ctx,
        },
        &Options{
            Hash:    crypto.Hash(0),
            Context: ctx,
        },
        &Options{
            Hash:    crypto.Hash(0),
            Context: "",
        },
    }

    for _, opts := range optses {
        useEdDSASign(t, opts)
    }
}
