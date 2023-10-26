package ecdsa

import (
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var (
    prikeyRC2_40En = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHsMFcGCSqGSIb3DQEFDTBKMCwGCSqGSIb3DQEFDDAfBAjk0K/kBxWT5QICCAAC
AQUwDAYIKoZIhvcNAgkFADAaBggqhkiG9w0DAjAOAgIAoAQIBEFHIZavVI4EgZC8
IHlYxzwKiFgmesGsBKdVEXTcWTrOFt5bNWhXBgrvx8hwPTedO+S6P+s3QWIVc/Nc
zRIqP3untcWttl58NH4AoMzcluRotnvPIT+uDQZmGais6gNuTNQLC4mH5iwG1SU/
uUGD5lTtbnyPV6nwqXxMHeEyKBHEQTnLN2dCtQ+uPemObYy2PsycbBrkmnFSqJg=
-----END ENCRYPTED PRIVATE KEY-----
    `
    prikeyRC2_64En = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHrMFYGCSqGSIb3DQEFDTBJMCwGCSqGSIb3DQEFDDAfBAjc42hKhwyUggICCAAC
AQgwDAYIKoZIhvcNAgkFADAZBggqhkiG9w0DAjANAgF4BAjNKncl5kKKCQSBkAAB
AGUBrfFFjqKbQEboQJEdUUejEftP3+9vaFWpFMjnsZQArk+CUY0CEkdiA3nM1DrF
doHv3Y2ZUOG1fDMirxSuol4A1Rn7j/x77CStgnQWC5EevgzurYrXSMqOoHeFvHmr
EjglBZmJZhlvRDfAosWXdUK0KLHoOc/yEsZVAwYU+rrIZ0zxvSOGI9Gwg5+PFg==
-----END ENCRYPTED PRIVATE KEY-----
    `
    prikeyRC2_128En = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHrMFYGCSqGSIb3DQEFDTBJMCwGCSqGSIb3DQEFDDAfBAjrHsbwZM9hiAICCAAC
ARAwDAYIKoZIhvcNAgkFADAZBggqhkiG9w0DAjANAgE6BAhCcTJyS4lSkQSBkD8o
D/uvTv+qICayIkesG7MTJxnwKBCEQSvT6VaDr+h886WZyLsNpAizAt7KO9nGeYx0
PozXsuN1lbb5IWpJYPokCbc2cPBNAtjVXHhzEAjWiYx35fjmrhhThU51oJsNs0Vs
7lBmGCkJ0qMxtghYl5GbOQgxolndmWUY+kI6wD4zHPCfxSbmeguEIHPVEt9H7Q==
-----END ENCRYPTED PRIVATE KEY-----
    `

    prikeyRC5_128En = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIH2MGEGCSqGSIb3DQEFDTBUMDQGCSqGSIb3DQEFDDAnBBDXhwsCPrGvseRydsuL
ZXeXAgInEAIBEDAMBggqhkiG9w0CBwUAMBwGCCqGSIb3DQMJMBACASACARAECJYx
0ig68wlGBIGQ/+gW/1WRg9+sUZVeM3yhTm632foxSo2t0M6LUCpvfhHzawkhKAgv
TwodpmMQyT6a0ejB0ltbnLmFMIB3VaftT4h9ORLsybec6IYZctF8F2g9hH7d12sl
F7pNrsppYE/faVT+XgQXFf5vdCv4k6jPYylXuiS/2SX7dJiKPjZ4ajWlgo47rj+h
noDr6RanB06B
-----END ENCRYPTED PRIVATE KEY-----
    `
    prikeyRC5_192En = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIH2MGEGCSqGSIb3DQEFDTBUMDQGCSqGSIb3DQEFDDAnBBD0UHLPhL6izdN/CKEA
lXroAgInEAIBGDAMBggqhkiG9w0CBwUAMBwGCCqGSIb3DQMJMBACASACARAECCjg
IYtxKW10BIGQ1zM06HpkxfguYnwizlqvARb2r90mN3LNa8LSUxahA1O8Uoym34ma
mrL/teAQCsIvw+ZwzCWhsOkiMk864MHQ5Yn4sp+zI43C78ohsspdPiZkG2WwZXLx
dlwGyyi6u16OeBK130Dct44glMYJwrhh5/TYNECQOZdVFMEGrppqQ7n/I1doWauc
TM6gkDylMwGA
-----END ENCRYPTED PRIVATE KEY-----
    `
    prikeyRC5_256En = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIH2MGEGCSqGSIb3DQEFDTBUMDQGCSqGSIb3DQEFDDAnBBBzOzXX48hxGPNecO39
VmR8AgInEAIBIDAMBggqhkiG9w0CBwUAMBwGCCqGSIb3DQMJMBACASACARAECBf+
FMy4z8JdBIGQBRa1SZUFiCqAeyBNNffxv7pFxP33kgTB5aTbmiCxnOIe0uhWWecY
bHfoEmQOIWYKYCpWrAqekL7GfGsHUPW6ELghEqvLbEYv2DM13tX1y2LkKMlCjicH
bWTvUcRO3XUuDDmQT9dgwGJSK8tvq/nJRJzCdSJ0VtYYwH7NTupAxKI4BvFdNkHS
HWvTSAna+Tu8
-----END ENCRYPTED PRIVATE KEY-----
    `

    pubkeyEn = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqktVUz5Og3mBcnhpnfWWSOhrZqO+
Vu0zCh5hkl/0r9vPzPeqGpHJv3eJw/zF+gZWxn2LvLcKkQTcGutSwVdVRQ==
-----END PUBLIC KEY-----
    `
)

func Test_SignASN1_RC2_40En(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"
    objSign := NewEcdsa().
        FromString(data).
        FromPrivateKeyWithPassword([]byte(prikeyRC2_40En), "123").
        SignASN1()

    assertError(objSign.Error(), "SignASN1_RC2_40En-SignASN1")
    assertNotEmpty(objSign.ToBase64String(), "SignASN1_RC2_40En-SignASN1")
}

func Test_SignASN1_RC2_64En(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"
    objSign := NewEcdsa().
        FromString(data).
        FromPrivateKeyWithPassword([]byte(prikeyRC2_64En), "123").
        SignASN1()

    assertError(objSign.Error(), "SignASN1_RC2_64En-SignASN1")
    assertNotEmpty(objSign.ToBase64String(), "SignASN1_RC2_64En-SignASN1")
}

func Test_SignASN1_RC2_128En(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"
    objSign := NewEcdsa().
        FromString(data).
        FromPrivateKeyWithPassword([]byte(prikeyRC2_128En), "123").
        SignASN1()

    assertError(objSign.Error(), "SignASN1_RC2_128En-SignASN1")
    assertNotEmpty(objSign.ToBase64String(), "SignASN1_RC2_128En-SignASN1")
}

func Test_SignASN1_RC5_256En(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"
    objSign := NewEcdsa().
        FromString(data).
        FromPrivateKeyWithPassword([]byte(prikeyRC5_256En), "123").
        SignASN1()

    assertError(objSign.Error(), "SignASN1_RC5_256En-SignASN1")
    assertNotEmpty(objSign.ToBase64String(), "SignASN1_RC5_256En-SignASN1")
}

func Test_SignASN1_RC5_192En(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"
    objSign := NewEcdsa().
        FromString(data).
        FromPrivateKeyWithPassword([]byte(prikeyRC5_192En), "123").
        SignASN1()

    assertError(objSign.Error(), "SignASN1_RC5_192En-SignASN1")
    assertNotEmpty(objSign.ToBase64String(), "SignASN1_RC5_192En-SignASN1")
}

func Test_SignASN1_RC5_128En(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertBool := cryptobin_test.AssertBoolT(t)

    data := "test-pass"
    objSign := NewEcdsa().
        FromString(data).
        FromPrivateKeyWithPassword([]byte(prikeyRC5_128En), "123").
        SignASN1()
    signedData := objSign.ToBase64String()

    assertError(objSign.Error(), "SignASN1_RC5_128En-SignASN1")
    assertNotEmpty(signedData, "SignASN1_RC5_128En-SignASN1")

    objVerify := NewEcdsa().
        FromBase64String(signedData).
        FromPrivateKeyWithPassword([]byte(prikeyRC5_128En), "123").
        MakePublicKey().
        VerifyASN1([]byte(data))

    assertError(objVerify.Error(), "SignASN1_RC5_128En-VerifyASN1")
    assertBool(objVerify.ToVerify(), "SignASN1_RC5_128En-VerifyASN1")
}

func Test_VerifyASN1En(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertBool := cryptobin_test.AssertBoolT(t)

    data := "test-pass"
    sig := "MEUCIBhAZzrS6jM4MfwibzA+j0vBkTEQGvkiDWhx7E6/ePUmAiEAt1uTZXUPGNU9nY8ZS3UxcJCRqwh/G8eeyrAVwM3qen4="
    objVerify := NewEcdsa().
        FromBase64String(sig).
        FromPublicKey([]byte(pubkeyEn)).
        VerifyASN1([]byte(data))

    assertError(objVerify.Error(), "VerifyASN1En-VerifyASN1")
    assertBool(objVerify.ToVerify(), "VerifyASN1En-VerifyASN1")
}
