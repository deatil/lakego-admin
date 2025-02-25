package eddsa

import (
    "crypto"
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var (
    testPrikey = `
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIFEs/Su+yy7RjO04AIsq7x+Bg9NRq1FFykJe7gPJXqWY
-----END PRIVATE KEY-----
    `
    testPubkey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAvJgQNRwfWO53Hy2vSaBlz4wytmobPga00sRKaYenmgQ=
-----END PUBLIC KEY-----
`

    testPrikeyEn = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIGjMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBA4MT4RO/TanOhtYFlU
5YeVAgInEDAMBggqhkiG9w0CBwUAMB0GCWCGSAFlAwQBAgQQvSN7URYWp8xlhIaL
t6K47wRALJ6ATPXrLQ8DGCAax2llMsB9TFJPAqnZX+lkdtzEELCaDpmkd/O9EYc3
Fv7U+2E59pDpj3Vmen2xaKZ30xdpTQ==
-----END ENCRYPTED PRIVATE KEY-----
    `
    testPubkeyEn = `
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAPZhFbGV49GRe/V0OHRimYBNT9EyL+fNYYKRXblB5VMw=
-----END PUBLIC KEY-----
    `

)

func useEdDSASign(t *testing.T, opts *Options) {
    assertTrue := cryptobin_test.AssertTrueT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    data := []byte("test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass3333333333333333333333333333333333333333333333333333test-pa2222222222222222222222222222222222222222222sstest-passt111111111111111111111111111111111est-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passt-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass")

    hashed := FromBytes(data).
        FromPrivateKey([]byte(testPrikey)).
        WithOptions(opts).
        Sign()
    hashedData := hashed.ToBase64String()

    assertNoError(hashed.Error(), "EdDSASign-Sign")
    assertNotEmpty(hashedData, "EdDSASign-Sign")

    // ===

    dehashed := FromBase64String(hashedData).
        FromPublicKey([]byte(testPubkey)).
        WithOptions(opts).
        Verify(data)
    dehashedVerify := dehashed.ToVerify()

    assertNoError(dehashed.Error(), "EdDSASign-Verify")
    assertTrue(dehashedVerify, "EdDSASign-Verify")
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
