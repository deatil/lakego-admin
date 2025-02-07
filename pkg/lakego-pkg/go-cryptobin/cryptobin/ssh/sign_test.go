package ssh

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
    assertTrue := cryptobin_test.AssertTrueT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    data := "test-pass"

    // 签名
    objSign := New().
        FromString(data).
        FromOpenSSHPrivateKey([]byte(prikey)).
        Sign()
    signed := objSign.ToString()

    assertNoError(objSign.Error(), "Sign-Sign")
    assertNotEmpty(signed, "Sign-Sign")

    // 验证
    objVerify := New().
        FromString(signed).
        FromOpenSSHPublicKey([]byte(pubkey)).
        Verify([]byte(data))

    assertNoError(objVerify.Error(), "Sign-Verify")
    assertTrue(objVerify.ToVerify(), "Sign-Verify")
}

func Test_Sign_Check(t *testing.T) {
    assertTrue := cryptobin_test.AssertTrueT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

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
        FromOpenSSHPublicKey([]byte(pubkey)).
        Verify([]byte(data))

    assertNoError(objVerify.Error(), "Sign-Verify")
    assertTrue(objVerify.ToVerify(), "Sign-Verify")
}

func Test_CheckKeyPair(t *testing.T) {
    assertTrue := cryptobin_test.AssertTrueT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    {
        obj := New().
            FromOpenSSHPrivateKey([]byte(prikey)).
            FromOpenSSHPublicKey([]byte(pubkey))

        assertNoError(obj.Error(), "CheckKeyPair")
        assertTrue(obj.CheckKeyPair(), "CheckKeyPair")
    }

    {
        obj := New().
            FromOpenSSHPrivateKey([]byte(prikey)).
            FromOpenSSHPublicKey([]byte(pubkey2))

        assertNoError(obj.Error(), "CheckKeyPair 2")
        assertTrue(!obj.CheckKeyPair(), "CheckKeyPair 2")
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
    assertTrue := cryptobin_test.AssertTrueT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj0 := New().SetPublicKeyType(keyType).GenerateKey()
    assertNoError(obj0.Error(), "test_CheckKeyPair2")

    prikey := obj0.CreateOpenSSHPrivateKey().ToKeyBytes()
    assertNotEmpty(prikey, "test_CheckKeyPair2-PrivateKey")

    pubkey := obj0.CreateOpenSSHPublicKey().ToKeyBytes()
    assertNotEmpty(pubkey, "test_CheckKeyPair2-PublicKey")

    obj := New().
        FromOpenSSHPrivateKey(prikey).
        FromOpenSSHPublicKey(pubkey)

    assertNoError(obj.Error(), "test_CheckKeyPair2")
    assertTrue(obj.CheckKeyPair(), "test_CheckKeyPair2")
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
    assertTrue := cryptobin_test.AssertTrueT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    data := "test-pass"

    obj0 := New().SetPublicKeyType(keyType).GenerateKey()
    assertNoError(obj0.Error(), "test_Sign2")

    prikey := obj0.CreateOpenSSHPrivateKey().ToKeyBytes()
    assertNotEmpty(prikey, "test_Sign2-PrivateKey")

    pubkey := obj0.CreateOpenSSHPublicKey().ToKeyBytes()
    assertNotEmpty(pubkey, "test_Sign2-PublicKey")

    // 签名
    objSign := New().
        FromString(data).
        FromOpenSSHPrivateKey(prikey).
        Sign()
    signed := objSign.ToString()

    assertNoError(objSign.Error(), "test_Sign2-Sign")
    assertNotEmpty(signed, "test_Sign2-Sign")

    // 验证
    objVerify := New().
        FromString(signed).
        FromOpenSSHPublicKey(pubkey).
        Verify([]byte(data))

    assertNoError(objVerify.Error(), "test_Sign2-Verify")
    assertTrue(objVerify.ToVerify(), "test_Sign2-Verify")
}
