package gost

import (
    "testing"
    "crypto/rand"
    "encoding/hex"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func decodeHex(s string) []byte {
    res, _ := hex.DecodeString(s)
    return res
}

var testPEMCiphers = []string{
    "DESEDE3CBC",
    "AES256CBC",
}

func Test_CreatePKCS8PrivateKeyWithPassword(t *testing.T) {
    gen := GenerateKey("CurveIdGostR34102001CryptoProAParamSet")

    for _, cipher := range testPEMCiphers {
        test_CreatePKCS8PrivateKeyWithPassword(t, gen, cipher)
    }
}

func test_CreatePKCS8PrivateKeyWithPassword(t *testing.T, gen Gost, cipher string) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    t.Run(cipher, func(t *testing.T) {
        pass := make([]byte, 12)
        _, err := rand.Read(pass)
        if err != nil {
            t.Fatal(err)
        }

        prikey := gen.GetPrivateKey()

        pri := gen.
            CreatePKCS8PrivateKeyWithPassword(string(pass), cipher).
            ToKeyString()

        assertError(gen.Error(), "Test_CreatePKCS8PrivateKeyWithPassword")
        assertNotEmpty(pri, "Test_CreatePKCS8PrivateKeyWithPassword-pri")

        newPrikey := New().
            FromPKCS8PrivateKeyWithPassword([]byte(pri), string(pass)).
            GetPrivateKey()

        assertNotEmpty(newPrikey, "Test_CreatePKCS8PrivateKeyWithPassword-newPrikey")

        assertEqual(newPrikey, prikey, "Test_CreatePKCS8PrivateKeyWithPassword")
    })
}

func Test_CreatePublicKey(t *testing.T) {
    gen := GenerateKey("CurveIdGostR34102001CryptoProAParamSet")

    for _, cipher := range testPEMCiphers {
        test_CreatePublicKey(t, gen, cipher)
    }
}

func test_CreatePublicKey(t *testing.T, gen Gost, cipher string) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    t.Run(cipher, func(t *testing.T) {
        pass := make([]byte, 12)
        _, err := rand.Read(pass)
        if err != nil {
            t.Fatal(err)
        }

        pubkey := gen.GetPublicKey()

        pub := gen.
            CreatePublicKey().
            ToKeyString()

        assertError(gen.Error(), "Test_CreatePublicKey")
        assertNotEmpty(pub, "Test_CreatePublicKey-pub")

        newPubkey := New().
            FromPublicKey([]byte(pub)).
            GetPublicKey()

        assertNotEmpty(newPubkey, "Test_CreatePublicKey-newPubkey")

        assertEqual(newPubkey, pubkey, "Test_CreatePublicKey")
    })
}

func Test_Sign(t *testing.T) {
    types := []string{
        "CurveIdGostR34102001CryptoProAParamSet",
        "CurveIdtc26gost34102012256paramSetC",
    }

    for _, name := range types {
        t.Run(name, func(t *testing.T) {
            gen := GenerateKey(name)
            test_Sign(t, gen)
        })
    }
}

func test_Sign(t *testing.T, gen Gost) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"

    // 签名
    objSign := gen.
        FromString(data).
        Sign()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "Sign-Sign")
    assertNotEmpty(signed, "Sign-Sign")

    // 验证
    objVerify := gen.
        FromBase64String(signed).
        Verify([]byte(data))

    assertError(objVerify.Error(), "Sign-Verify")
    assertBool(objVerify.ToVerify(), "Sign-Verify")
}

func Test_SignASN1(t *testing.T) {
    types := []string{
        "CurveIdGostR34102001CryptoProAParamSet",
        "CurveIdtc26gost34102012256paramSetC",
    }

    for _, name := range types {
        t.Run(name, func(t *testing.T) {
            gen := GenerateKey(name)
            test_SignASN1(t, gen)
        })
    }
}

func test_SignASN1(t *testing.T, gen Gost) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"

    // 签名
    objSign := gen.
        FromString(data).
        SignASN1()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "SignASN1-Sign")
    assertNotEmpty(signed, "SignASN1-Sign")

    // 验证
    objVerify := gen.
        FromBase64String(signed).
        VerifyASN1([]byte(data))

    assertError(objVerify.Error(), "SignASN1-Verify")
    assertBool(objVerify.ToVerify(), "SignASN1-Verify")
}

func Test_MakeKey(t *testing.T) {
    gen := GenerateKey("CurveIdtc26gost34102012256paramSetC")

    prikey := gen.
        CreatePKCS8PrivateKey().
        ToKeyString()

    if len(prikey) == 0 {
        t.Error("make prikey fail")
    }
}

func Test_Vko_KEK(t *testing.T) {
    gen1 := GenerateKey("CurveIdtc26gost34102012256paramSetC")
    gen2 := GenerateKey("CurveIdtc26gost34102012256paramSetC")

    ukm := "123456"

    secret1 := New().
        WithPrivateKey(gen1.GetPrivateKey()).
        WithPublicKey(gen2.GetPublicKey()).
        KEK(ukm).
        ToSecretString()
    secret2 := New().
        WithPrivateKey(gen2.GetPrivateKey()).
        WithPublicKey(gen1.GetPublicKey()).
        KEK(ukm).
        ToSecretString()

    if len(secret1) == 0 {
        t.Error("make secret1 fail")
    }
    if len(secret2) == 0 {
        t.Error("make secret2 fail")
    }

    if secret1 != secret2 {
        t.Error("secret1 not equal secret2")
    }
}

func Test_Vko_KEK2001(t *testing.T) {
    gen1 := GenerateKey("CurveIdtc26gost34102012256paramSetC")
    gen2 := GenerateKey("CurveIdtc26gost34102012256paramSetC")

    ukm := "123456"

    secret1 := New().
        WithPrivateKey(gen1.GetPrivateKey()).
        WithPublicKey(gen2.GetPublicKey()).
        KEK2001(ukm).
        ToSecretString()
    secret2 := New().
        WithPrivateKey(gen2.GetPrivateKey()).
        WithPublicKey(gen1.GetPublicKey()).
        KEK2001(ukm).
        ToSecretString()

    if len(secret1) == 0 {
        t.Error("make secret1 fail")
    }
    if len(secret2) == 0 {
        t.Error("make secret2 fail")
    }

    if secret1 != secret2 {
        t.Error("secret1 not equal secret2")
    }
}

func Test_Vko_KEK2012256(t *testing.T) {
    gen1 := GenerateKey("CurveIdtc26gost34102012256paramSetC")
    gen2 := GenerateKey("CurveIdtc26gost34102012256paramSetC")

    ukm := "123456"

    secret1 := New().
        WithPrivateKey(gen1.GetPrivateKey()).
        WithPublicKey(gen2.GetPublicKey()).
        KEK2012256(ukm).
        ToSecretString()
    secret2 := New().
        WithPrivateKey(gen2.GetPrivateKey()).
        WithPublicKey(gen1.GetPublicKey()).
        KEK2012256(ukm).
        ToSecretString()

    if len(secret1) == 0 {
        t.Error("make secret1 fail")
    }
    if len(secret2) == 0 {
        t.Error("make secret2 fail")
    }

    if secret1 != secret2 {
        t.Error("secret1 not equal secret2")
    }
}

func Test_Vko_KEK2012512(t *testing.T) {
    gen1 := GenerateKey("CurveIdtc26gost34102012256paramSetC")
    gen2 := GenerateKey("CurveIdtc26gost34102012256paramSetC")

    ukm := "123456"

    secret1 := New().
        WithPrivateKey(gen1.GetPrivateKey()).
        WithPublicKey(gen2.GetPublicKey()).
        KEK2012512(ukm).
        ToSecretString()
    secret2 := New().
        WithPrivateKey(gen2.GetPrivateKey()).
        WithPublicKey(gen1.GetPublicKey()).
        KEK2012512(ukm).
        ToSecretString()

    if len(secret1) == 0 {
        t.Error("make secret1 fail")
    }
    if len(secret2) == 0 {
        t.Error("make secret2 fail")
    }

    if secret1 != secret2 {
        t.Error("secret1 not equal secret2")
    }
}

func Test_MakePriKeyFromData(t *testing.T) {
    pri := decodeHex("7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28")

    prikey := New().
        SetCurve("CurveIdGostR34102001TestParamSet").
        FromPrivateKeyBytes(pri).
        CreatePrivateKey().
        ToKeyString()

    if len(prikey) == 0 {
        t.Error("make prikey fail")
    }
}
