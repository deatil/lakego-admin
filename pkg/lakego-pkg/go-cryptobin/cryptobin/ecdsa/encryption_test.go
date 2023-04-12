package ecdsa

import (
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var (
    enprikey = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGfqpFWW2kecvy/V0mxus+ZMuODGcqfyZVJMgBbWRhYJoAoGCCqGSM49
AwEHoUQDQgAEqktVUz5Og3mBcnhpnfWWSOhrZqO+Vu0zCh5hkl/0r9vPzPeqGpHJ
v3eJw/zF+gZWxn2LvLcKkQTcGutSwVdVRQ==
-----END EC PRIVATE KEY-----
    `

    enpubkey = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqktVUz5Og3mBcnhpnfWWSOhrZqO+
Vu0zCh5hkl/0r9vPzPeqGpHJv3eJw/zF+gZWxn2LvLcKkQTcGutSwVdVRQ==
-----END PUBLIC KEY-----
    `
)

func Test_Encrypt(t *testing.T) {
    assertEmpty := cryptobin_test.AssertEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"
    obj := NewEcdsa().
        FromString(data).
        FromPublicKey([]byte(enpubkey)).
        Encrypt()

    assertError(obj.Error(), "Encrypt")
    assertEmpty(obj.ToBase64String(), "Encrypt")
}

func Test_Decrypt(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)

    data := "test-pass"
    endata := "BA6UmWJHLf/XOhge8ASuz11cMpX3YCu6Pfmp5tQ/OPK7rV27paYGB6V5vL/KhjVGznedvhGe0F3CNzoyxfp+r+41m+ehtIC0isWnDc8ZyZrmNVioOeaO5i6yEwiEwhTB8QzUSDE5JJB6ta0vObhBvFRVvgzv1VD0C4Y="
    obj := NewEcdsa().
        FromBase64String(endata).
        FromPrivateKey([]byte(enprikey)).
        Decrypt()

    assertError(obj.Error(), "Decrypt")
    assertEqual(obj.ToString(), data, "Decrypt")
}
