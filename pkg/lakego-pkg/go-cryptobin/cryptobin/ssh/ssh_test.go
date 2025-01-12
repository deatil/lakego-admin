package ecgdsa

import (
    "testing"
    "crypto/dsa"
    "crypto/elliptic"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_GenKey(t *testing.T) {
    cases := []string{
        "RSA",
        "DSA",
        "ECDSA",
        "EdDSA",
        "SM2",
    }

    for _, c := range cases {
        t.Run(c, func(t *testing.T) {
            test_GenKey(t, c)
        })
    }
}

func test_GenKey(t *testing.T, keyType string) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := New().SetPublicKeyType(keyType).GenerateKey()
    assertError(obj.Error(), "Test_GenKey")

    {
        prikey := obj.CreateOpensshPrivateKey().ToKeyBytes()
        assertNotEmpty(prikey, "Test_GenKey-PrivateKey")

        pubkey := obj.CreateOpensshPublicKey().ToKeyBytes()
        assertNotEmpty(pubkey, "Test_GenKey-PublicKey")

        // t.Errorf("%s, %s \n", string(prikey), string(pubkey))

        newSSH := New().FromOpensshPrivateKey(prikey)
        assertError(newSSH.Error(), "Test_GenKey-newSSH")

        assertEqual(newSSH.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey-newSSH")

        newSSH2 := New().FromOpensshPublicKey(pubkey)
        assertError(newSSH2.Error(), "Test_GenKey-newSSH2")

        assertEqual(newSSH2.GetPublicKey(), obj.GetPublicKey(), "Test_GenKey-newSSH2")
    }

    {
        password := []byte("test-password")

        prikey3 := obj.CreateOpensshPrivateKeyWithPassword(password).ToKeyBytes()
        assertNotEmpty(prikey3, "Test_GenKey-PrivateKey 3")

        newSSH3 := New().FromOpensshPrivateKeyWithPassword(prikey3, password)
        assertError(newSSH3.Error(), "Test_GenKey-newSSH3")

        assertEqual(newSSH3.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey-newSSH3")
    }
}

func Test_GenKey2(t *testing.T) {
    cases := []string{
        "RSA",
        "DSA",
        "ECDSA",
        "EdDSA",
        "SM2",
    }

    for _, c := range cases {
        t.Run(c, func(t *testing.T) {
            test_GenKey2(t, c)
        })
    }
}

func test_GenKey2(t *testing.T, keyType string) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := New().SetPublicKeyType(keyType).GenerateKey()
    assertError(obj.Error(), "Test_GenKey")

    {
        prikey := obj.CreatePrivateKey().ToKeyBytes()
        assertNotEmpty(prikey, "Test_GenKey-PrivateKey")

        pubkey := obj.CreatePublicKey().ToKeyBytes()
        assertNotEmpty(pubkey, "Test_GenKey-PublicKey")

        // t.Errorf("%s, %s \n", string(prikey), string(pubkey))

        newSSH := New().FromPrivateKey(prikey)
        assertError(newSSH.Error(), "Test_GenKey-newSSH")

        assertEqual(newSSH.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey-newSSH")

        newSSH2 := New().FromPublicKey(pubkey)
        assertError(newSSH2.Error(), "Test_GenKey-newSSH2")

        assertEqual(newSSH2.GetPublicKey(), obj.GetPublicKey(), "Test_GenKey-newSSH2")
    }

    {
        password := []byte("test-password")

        prikey3 := obj.CreatePrivateKeyWithPassword(password).ToKeyBytes()
        assertNotEmpty(prikey3, "Test_GenKey-PrivateKey 3")

        newSSH3 := New().FromPrivateKeyWithPassword(prikey3, password)
        assertError(newSSH3.Error(), "Test_GenKey-newSSH3")

        assertEqual(newSSH3.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey-newSSH3")
    }
}

func Test_GenKey3(t *testing.T) {
    cases := []PublicKeyType{
        KeyTypeRSA,
        KeyTypeDSA,
        KeyTypeECDSA,
        KeyTypeEdDSA,
        KeyTypeSM2,
    }

    for _, c := range cases {
        t.Run(c.String(), func(t *testing.T) {
            test_GenKey3(t, c)
        })
    }
}

func test_GenKey3(t *testing.T, keyType PublicKeyType) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    newOpts := func(ktype PublicKeyType) Options {
        opt := Options{
            PublicKeyType:  ktype,
            ParameterSizes: dsa.L1024N160,
            Curve:          elliptic.P256(),
            Bits:           2048,
        }

        return opt
    }

    obj := GenerateKey(newOpts(keyType))
    assertError(obj.Error(), "Test_GenKey")

    {
        prikey := obj.CreatePrivateKey().ToKeyBytes()
        assertNotEmpty(prikey, "Test_GenKey-PrivateKey")

        pubkey := obj.CreatePublicKey().ToKeyBytes()
        assertNotEmpty(pubkey, "Test_GenKey-PublicKey")

        // t.Errorf("%s, %s \n", string(prikey), string(pubkey))

        newSSH := New().FromPrivateKey(prikey)
        assertError(newSSH.Error(), "Test_GenKey-newSSH")

        assertEqual(newSSH.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey-newSSH")

        newSSH2 := New().FromPublicKey(pubkey)
        assertError(newSSH2.Error(), "Test_GenKey-newSSH2")

        assertEqual(newSSH2.GetPublicKey(), obj.GetPublicKey(), "Test_GenKey-newSSH2")
    }

    {
        password := []byte("test-password")

        prikey3 := obj.CreatePrivateKeyWithPassword(password).ToKeyBytes()
        assertNotEmpty(prikey3, "Test_GenKey-PrivateKey 3")

        newSSH3 := New().FromPrivateKeyWithPassword(prikey3, password)
        assertError(newSSH3.Error(), "Test_GenKey-newSSH3")

        assertEqual(newSSH3.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey-newSSH3")
    }
}

func Test_GenKey_ECDSA(t *testing.T) {
    cases := []string{
        "P256",
        "P384",
        "P521",
    }

    for _, c := range cases {
        t.Run(c, func(t *testing.T) {
            test_GenKey_ECDSA(t, c)
        })
    }
}

func test_GenKey_ECDSA(t *testing.T, curve string) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := New().
        SetPublicKeyType("ECDSA").
        SetCurve(curve).
        GenerateKey()
    assertError(obj.Error(), "Test_GenKey_ECDSA")

    prikey := obj.CreatePrivateKey().ToKeyBytes()
    assertNotEmpty(prikey, "Test_GenKey_ECDSA-PrivateKey")

    pubkey := obj.CreatePublicKey().ToKeyBytes()
    assertNotEmpty(pubkey, "Test_GenKey_ECDSA-PublicKey")

    newSSH := New().FromPrivateKey(prikey)
    assertError(newSSH.Error(), "Test_GenKey_ECDSA-newSSH")

    assertEqual(newSSH.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey_ECDSA-newSSH")

    newSSH2 := New().FromPublicKey(pubkey)
    assertError(newSSH2.Error(), "Test_GenKey_ECDSA-newSSH2")

    assertEqual(newSSH2.GetPublicKey(), obj.GetPublicKey(), "Test_GenKey_ECDSA-newSSH2")
}

func Test_GenKey_ECDSA_With_Comment(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    comment := "test-comment"

    obj := New().
        SetPublicKeyType("ECDSA").
        GenerateKey()
    assertError(obj.Error(), "Test_GenKey_ECDSA_With_Comment")

    prikey := obj.WithComment(comment).
        CreatePrivateKey().
        ToKeyBytes()
    assertNotEmpty(prikey, "Test_GenKey_ECDSA_With_Comment-PrivateKey")

    pubkey := obj.WithComment(comment).
        CreatePublicKey().
        ToKeyBytes()
    assertNotEmpty(pubkey, "Test_GenKey_ECDSA_With_Comment-PublicKey")

    newSSH := New().FromPrivateKey(prikey)
    assertError(newSSH.Error(), "Test_GenKey_ECDSA_With_Comment-newSSH")

    assertEqual(newSSH.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey_ECDSA_With_Comment-newSSH")
    assertEqual(newSSH.GetComment(), comment, "Test_GenKey_ECDSA_With_Comment-newSSH-comment")

    newSSH2 := New().FromPublicKey(pubkey)
    assertError(newSSH2.Error(), "Test_GenKey_ECDSA_With_Comment-newSSH2")

    assertEqual(newSSH2.GetPublicKey(), obj.GetPublicKey(), "Test_GenKey_ECDSA_With_Comment-newSSH2")
    assertEqual(newSSH2.GetComment(), comment, "Test_GenKey_ECDSA_With_Comment-newSSH2-comment")
}
