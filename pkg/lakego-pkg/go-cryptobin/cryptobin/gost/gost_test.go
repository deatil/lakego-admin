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
    gen := GenerateKey("IdGostR34102001CryptoProAParamSet")

    for _, cipher := range testPEMCiphers {
        test_CreatePKCS8PrivateKeyWithPassword(t, gen, cipher)
    }
}

func test_CreatePKCS8PrivateKeyWithPassword(t *testing.T, gen Gost, cipher string) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
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

        assertNoError(gen.Error(), "Test_CreatePKCS8PrivateKeyWithPassword")
        assertNotEmpty(pri, "Test_CreatePKCS8PrivateKeyWithPassword-pri")

        newPrikey := New().
            FromPKCS8PrivateKeyWithPassword([]byte(pri), string(pass)).
            GetPrivateKey()

        assertNotEmpty(newPrikey, "Test_CreatePKCS8PrivateKeyWithPassword-newPrikey")

        assertEqual(newPrikey, prikey, "Test_CreatePKCS8PrivateKeyWithPassword")
    })
}

func Test_CreatePublicKey(t *testing.T) {
    gen := GenerateKey("IdGostR34102001CryptoProAParamSet")

    for _, cipher := range testPEMCiphers {
        test_CreatePublicKey(t, gen, cipher)
    }
}

func test_CreatePublicKey(t *testing.T, gen Gost, cipher string) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
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

        assertNoError(gen.Error(), "Test_CreatePublicKey")
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
        "IdGostR34102001CryptoProAParamSet",
        "Idtc26gost34102012256paramSetC",
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
    assertTrue := cryptobin_test.AssertTrueT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    data := "test-pass"

    // 签名
    objSign := gen.
        FromString(data).
        Sign()
    signed := objSign.ToBase64String()

    assertNoError(objSign.Error(), "Sign-Sign")
    assertNotEmpty(signed, "Sign-Sign")

    // 验证
    objVerify := gen.
        FromBase64String(signed).
        Verify([]byte(data))

    assertNoError(objVerify.Error(), "Sign-Verify")
    assertTrue(objVerify.ToVerify(), "Sign-Verify")
}

func Test_SignASN1(t *testing.T) {
    types := []string{
        "IdGostR34102001CryptoProAParamSet",
        "Idtc26gost34102012256paramSetC",
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
    assertTrue := cryptobin_test.AssertTrueT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    data := "test-pass"

    // 签名
    objSign := gen.
        FromString(data).
        SignASN1()
    signed := objSign.ToBase64String()

    assertNoError(objSign.Error(), "SignASN1-Sign")
    assertNotEmpty(signed, "SignASN1-Sign")

    // 验证
    objVerify := gen.
        FromBase64String(signed).
        VerifyASN1([]byte(data))

    assertNoError(objVerify.Error(), "SignASN1-Verify")
    assertTrue(objVerify.ToVerify(), "SignASN1-Verify")
}

func Test_SignBytes(t *testing.T) {
    types := []string{
        "IdGostR34102001CryptoProAParamSet",
        "Idtc26gost34102012256paramSetC",
    }

    for _, name := range types {
        t.Run(name, func(t *testing.T) {
            gen := GenerateKey(name)
            test_SignBytes(t, gen)
        })
    }
}

func test_SignBytes(t *testing.T, gen Gost) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertTrue := cryptobin_test.AssertTrueT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    data := "test-pass"

    // 签名
    objSign := gen.
        FromString(data).
        SignBytes()
    signed := objSign.ToBase64String()

    assertNoError(objSign.Error(), "SignBytes-Sign")
    assertNotEmpty(signed, "SignBytes-Sign")

    // 验证
    objVerify := gen.
        FromBase64String(signed).
        VerifyBytes([]byte(data))

    assertNoError(objVerify.Error(), "SignBytes-Verify")
    assertTrue(objVerify.ToVerify(), "SignBytes-Verify")
}

func Test_MakeKey(t *testing.T) {
    eq := cryptobin_test.AssertEqualT(t)

    gen := GenerateKey("Idtc26gost34102012256paramSetC")
    eq(gen.GetPrivateKey().Curve.Name, "id-tc26-gost-3410-2012-256-paramSetC", "MakeKey")

    prikey := gen.
        CreatePKCS8PrivateKey().
        ToKeyString()

    if len(prikey) == 0 {
        t.Error("make prikey fail")
    }
}

func Test_MakeKeys(t *testing.T) {
    eq := cryptobin_test.AssertEqualT(t)

    tests := map[string]string{
        "id-GostR3410-2001-TestParamSet": "IdGostR34102001TestParamSet",
        "id-GostR3410-2001-CryptoPro-A-ParamSet": "IdGostR34102001CryptoProAParamSet",
        "id-GostR3410-2001-CryptoPro-B-ParamSet": "IdGostR34102001CryptoProBParamSet",
        "id-GostR3410-2001-CryptoPro-C-ParamSet": "IdGostR34102001CryptoProCParamSet",
        "id-GostR3410-2001-CryptoPro-XchA-ParamSet": "IdGostR34102001CryptoProXchAParamSet",
        "id-GostR3410-2001-CryptoPro-XchB-ParamSet": "IdGostR34102001CryptoProXchBParamSet",
        "id-tc26-gost-3410-2012-256-paramSetA": "Idtc26gost34102012256paramSetA",
        "id-tc26-gost-3410-2012-256-paramSetB": "Idtc26gost34102012256paramSetB",
        "id-tc26-gost-3410-2012-256-paramSetC": "Idtc26gost34102012256paramSetC",
        "id-tc26-gost-3410-2012-256-paramSetD": "Idtc26gost34102012256paramSetD",
        "id-tc26-gost-3410-2012-512-paramSetTest": "Idtc26gost34102012512paramSetTest",
        "id-tc26-gost-3410-2012-512-paramSetA": "Idtc26gost34102012512paramSetA",
        "id-tc26-gost-3410-2012-512-paramSetB": "Idtc26gost34102012512paramSetB",
        "id-tc26-gost-3410-2012-512-paramSetC": "Idtc26gost34102012512paramSetC",
    }

    for name, td := range tests {
        t.Run("test " + td, func(t *testing.T) {
            gen := GenerateKey(td)
            eq(gen.GetPrivateKey().Curve.Name, name, "MakeKeys")

            err := gen.
                CreatePKCS8PrivateKey().
                Error()

            if err != nil {
                t.Error(err)
            }
        })
    }
}

func Test_Vko_KEK(t *testing.T) {
    eq := cryptobin_test.AssertEqualT(t)

    gen1 := GenerateKey("Idtc26gost34102012256paramSetC")
    gen2 := GenerateKey("Idtc26gost34102012256paramSetC")

    eq(gen1.GetPrivateKey().Curve.Name, "id-tc26-gost-3410-2012-256-paramSetC", "Test_Vko_KEK")
    eq(gen2.GetPrivateKey().Curve.Name, "id-tc26-gost-3410-2012-256-paramSetC", "Test_Vko_KEK")

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
    eq := cryptobin_test.AssertEqualT(t)

    gen1 := GenerateKey("Idtc26gost34102012256paramSetC")
    gen2 := GenerateKey("Idtc26gost34102012256paramSetC")

    eq(gen1.GetPrivateKey().Curve.Name, "id-tc26-gost-3410-2012-256-paramSetC", "Test_Vko_KEK2001")
    eq(gen2.GetPrivateKey().Curve.Name, "id-tc26-gost-3410-2012-256-paramSetC", "Test_Vko_KEK2001")

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
    eq := cryptobin_test.AssertEqualT(t)

    gen1 := GenerateKey("Idtc26gost34102012256paramSetC")
    gen2 := GenerateKey("Idtc26gost34102012256paramSetC")

    eq(gen1.GetPrivateKey().Curve.Name, "id-tc26-gost-3410-2012-256-paramSetC", "Test_Vko_KEK2012256")
    eq(gen2.GetPrivateKey().Curve.Name, "id-tc26-gost-3410-2012-256-paramSetC", "Test_Vko_KEK2012256")

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
    eq := cryptobin_test.AssertEqualT(t)

    gen1 := GenerateKey("Idtc26gost34102012256paramSetC")
    gen2 := GenerateKey("Idtc26gost34102012256paramSetC")

    eq(gen1.GetPrivateKey().Curve.Name, "id-tc26-gost-3410-2012-256-paramSetC", "Test_Vko_KEK2012512")
    eq(gen2.GetPrivateKey().Curve.Name, "id-tc26-gost-3410-2012-256-paramSetC", "Test_Vko_KEK2012512")

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
        SetCurve("IdGostR34102001TestParamSet").
        FromPrivateKeyBytes(pri).
        CreatePrivateKey().
        ToKeyString()

    if len(prikey) == 0 {
        t.Error("make prikey fail")
    }
}

func Test_UseKeyBytes(t *testing.T) {
    eq := cryptobin_test.AssertEqualT(t)

    gen := GenerateKey("Idtc26gost34102012256paramSetC")

    eq(gen.GetPrivateKey().Curve.Name, "id-tc26-gost-3410-2012-256-paramSetC", "Test_UseKeyBytes")

    pri0 := gen.GetPrivateKey()
    pub0 := gen.GetPublicKey()

    priBytes := gen.GetPrivateKeyBytes()
    pubBytes := gen.GetPublicKeyBytes()
    if len(priBytes) == 0 {
        t.Error("get priBytes fail")
    }
    if len(pubBytes) == 0 {
        t.Error("get pubBytes fail")
    }

    obj := New().SetCurve("Idtc26gost34102012256paramSetC")

    pri := obj.
        FromPrivateKeyBytes(priBytes).
        GetPrivateKey()
    pub := obj.
        FromPublicKeyBytes(pubBytes).
        GetPublicKey()

    if !pri.Equal(pri0) {
        t.Error("FromPrivateKeyBytes fail")
    }
    if !pub.Equal(pub0) {
        t.Error("FromPublicKeyBytes fail")
    }
}

func Test_EncodingType(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    var gost Gost

    gost = NewGost().WithEncoding(EncodingASN1)
    assertEqual(gost.encoding, EncodingASN1, "EncodingASN1 1")

    gost = NewGost().WithEncodingASN1()
    assertEqual(gost.encoding, EncodingASN1, "EncodingASN1")

    gost = NewGost().WithEncodingBytes()
    assertEqual(gost.encoding, EncodingBytes, "EncodingBytes")

    gost = Gost{
        encoding: EncodingASN1,
    }
    assertEqual(gost.GetEncoding(), EncodingASN1, "new EncodingASN1")

    gost = Gost{
        encoding: EncodingBytes,
    }
    assertEqual(gost.GetEncoding(), EncodingBytes, "new EncodingBytes")
}

func Test_SignWithEncoding(t *testing.T) {
    t.Run("EncodingASN1", func(t *testing.T) {
        test_SignWithEncoding(t, EncodingASN1)
    })
    t.Run("EncodingBytes", func(t *testing.T) {
        test_SignWithEncoding(t, EncodingBytes)
    })
}

func test_SignWithEncoding(t *testing.T, encoding EncodingType) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertTrue := cryptobin_test.AssertTrueT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    gen := GenerateKey("IdGostR34102001CryptoProAParamSet")

    data := "test-pass"

    // 签名
    objSign := gen.
        FromString(data).
        WithEncoding(encoding).
        Sign()
    signed := objSign.ToBase64String()

    assertNoError(objSign.Error(), "test_SignWithEncoding-Sign")
    assertNotEmpty(signed, "test_SignWithEncoding-Sign")

    // 验证
    objVerify := gen.
        FromBase64String(signed).
        WithEncoding(encoding).
        Verify([]byte(data))

    assertNoError(objVerify.Error(), "test_SignWithEncoding-Verify")
    assertTrue(objVerify.ToVerify(), "test_SignWithEncoding-Verify")
}

func Test_SignWithEncoding_Two_Check(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertNotEqual := cryptobin_test.AssertNotEqualT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"

    gen := GenerateKey("IdGostR34102001CryptoProAParamSet")

    // 签名
    objSign := gen.
        FromString(data).
        WithEncoding(EncodingASN1).
        Sign()
    signed := objSign.ToBase64String()

    assertNoError(objSign.Error(), "Test_SignWithEncoding_Two_Check-Sign")
    assertNotEmpty(signed, "Test_SignWithEncoding_Two_Check-Sign")

    // 签名
    objSign2 := gen.
        FromString(data).
        WithEncoding(EncodingBytes).
        Sign()
    signed2 := objSign2.ToBase64String()

    assertNoError(objSign2.Error(), "Test_SignWithEncoding_Two_Check-Sign")
    assertNotEmpty(signed2, "Test_SignWithEncoding_Two_Check-Sign")

    assertNotEqual(signed2, signed, "Test_SignWithEncoding_Two_Check")
}
