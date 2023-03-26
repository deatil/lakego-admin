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
    assertEmpty := cryptobin_test.AssertEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"
    objSign := NewEcdsa().
        FromString(data).
        FromPrivateKey([]byte(prikey)).
        SignASN1()

    assertError(objSign.Error(), "SignASN1")
    assertEmpty(objSign.ToBase64String(), "SignASN1")
}

func Test_VerifyASN1(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertBool := cryptobin_test.AssertBoolT(t)

    data := "test-pass"
    sig := "MEUCIQDMFy5iaMybaRdfRBTWeHHipBdiOEIW1xK8qA6V3yYq2AIgBQZ+Dffhr822X37nRLKNbbnWH4ioVUCcPpBScoxQpVE="
    objVerify := NewEcdsa().
        FromBase64String(sig).
        FromPublicKey([]byte(pubkey)).
        VerifyASN1([]byte(data))

    assertError(objVerify.Error(), "VerifyASN1")
    assertBool(objVerify.ToVerify(), "VerifyASN1")
}
