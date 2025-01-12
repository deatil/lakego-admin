package ecgdsa

import (
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var (
    prikey = `
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACADjXFGIcSTKap9+8F1Z0jH26A8WtUD9nogUD8fKgNitQAA
AIPzVi9B81YvQQAAAAtzc2gtZWQyNTUxOQAAACADjXFGIcSTKap9+8F1Z0jH26A8
WtUD9nogUD8fKgNitQAAAEBtYVGTSuL9/OEtFMPDkvdKNpzcbliZhDiZAMr12VxO
2QONcUYhxJMpqn37wXVnSMfboDxa1QP2eiBQPx8qA2K1AAAAAA==
-----END OPENSSH PRIVATE KEY-----
    `

    pubkey = `
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAONcUYhxJMpqn37wXVnSMfboDxa1QP2eiBQPx8qA2K1
    `

    pubkey2 = `
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL5YLiGEuiHIP3p8Uvz0mCQXP9YtN/TS7vUcc0D+BA76
    `
)

func Test_Sign(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"

    // 签名
    objSign := New().
        FromString(data).
        FromOpensshPrivateKey([]byte(prikey)).
        Sign()
    signed := objSign.ToString()

    assertError(objSign.Error(), "Sign-Sign")
    assertNotEmpty(signed, "Sign-Sign")

    // 验证
    objVerify := New().
        FromString(signed).
        FromOpensshPublicKey([]byte(pubkey)).
        Verify([]byte(data))

    assertError(objVerify.Error(), "Sign-Verify")
    assertBool(objVerify.ToVerify(), "Sign-Verify")
}

func Test_Sign_Check(t *testing.T) {
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"

    signed := `
-----BEGIN OPENSSH SIGNATURE-----
Format: ssh-ed25519

N85866utz9/+tNzFvpN6zjz7yMlBy9ONXBe9wKayFGykXBQVoqBKQcb+hcwPh/pA
c5pto6ZM6K74kS1PDb04CQ==
-----END OPENSSH SIGNATURE-----
    `

    // 验证
    objVerify := New().
        FromString(signed).
        FromOpensshPublicKey([]byte(pubkey)).
        Verify([]byte(data))

    assertError(objVerify.Error(), "Sign-Verify")
    assertBool(objVerify.ToVerify(), "Sign-Verify")
}

func Test_CheckKeyPair(t *testing.T) {
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    {
        obj := New().
            FromOpensshPrivateKey([]byte(prikey)).
            FromOpensshPublicKey([]byte(pubkey))

        assertError(obj.Error(), "CheckKeyPair")
        assertBool(obj.CheckKeyPair(), "CheckKeyPair")
    }

    {
        obj := New().
            FromOpensshPrivateKey([]byte(prikey)).
            FromOpensshPublicKey([]byte(pubkey2))

        assertError(obj.Error(), "CheckKeyPair 2")
        assertBool(!obj.CheckKeyPair(), "CheckKeyPair 2")
    }

}

func Test_CheckKeyPair2(t *testing.T) {
    cases := []string{
        "RSA",
        "DSA",
        "ECDSA",
        "EdDSA",
        "SM2",
    }

    for _, c := range cases {
        t.Run(c, func(t *testing.T) {
            test_CheckKeyPair2(t, c)
        })
    }
}

func test_CheckKeyPair2(t *testing.T, keyType string) {
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj0 := New().SetPublicKeyType(keyType).GenerateKey()
    assertError(obj0.Error(), "test_CheckKeyPair2")

    prikey := obj0.CreateOpensshPrivateKey().ToKeyBytes()
    assertNotEmpty(prikey, "test_CheckKeyPair2-PrivateKey")

    pubkey := obj0.CreateOpensshPublicKey().ToKeyBytes()
    assertNotEmpty(pubkey, "test_CheckKeyPair2-PublicKey")

    obj := New().
        FromOpensshPrivateKey(prikey).
        FromOpensshPublicKey(pubkey)

    assertError(obj.Error(), "test_CheckKeyPair2")
    assertBool(obj.CheckKeyPair(), "test_CheckKeyPair2")
}

func Test_Sign2(t *testing.T) {
    cases := []string{
        "RSA",
        "DSA",
        "ECDSA",
        "EdDSA",
        "SM2",
    }

    for _, c := range cases {
        t.Run(c, func(t *testing.T) {
            test_Sign2(t, c)
        })
    }
}

func test_Sign2(t *testing.T, keyType string) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"

    obj0 := New().SetPublicKeyType(keyType).GenerateKey()
    assertError(obj0.Error(), "test_Sign2")

    prikey := obj0.CreateOpensshPrivateKey().ToKeyBytes()
    assertNotEmpty(prikey, "test_Sign2-PrivateKey")

    pubkey := obj0.CreateOpensshPublicKey().ToKeyBytes()
    assertNotEmpty(pubkey, "test_Sign2-PublicKey")

    // 签名
    objSign := New().
        FromString(data).
        FromOpensshPrivateKey(prikey).
        Sign()
    signed := objSign.ToString()

    assertError(objSign.Error(), "test_Sign2-Sign")
    assertNotEmpty(signed, "test_Sign2-Sign")

    // 验证
    objVerify := New().
        FromString(signed).
        FromOpensshPublicKey(pubkey).
        Verify([]byte(data))

    assertError(objVerify.Error(), "test_Sign2-Verify")
    assertBool(objVerify.ToVerify(), "test_Sign2-Verify")
}
