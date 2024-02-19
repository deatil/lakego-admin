package sm2

import (
    "testing"
    "crypto/md5"
    "crypto/rand"
    "encoding/hex"
    "encoding/base64"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_SignBytesWithHashFunc(t *testing.T) {
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    data := "test-pass"
    uid := []byte("N003261207000000")

    gen := GenerateKey()

    // 签名
    objSign := gen.
        FromString(data).
        WithSignHash(md5.New).
        SignBytes(uid)
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "SignBytesWithHashFunc-Sign")
    assertNotEmpty(signed, "SignBytesWithHashFunc-Sign")

    // 验证
    objVerify := gen.
        FromBase64String(signed).
        WithSignHash(md5.New).
        VerifyBytes([]byte(data), uid)

    assertError(objVerify.Error(), "SignBytesWithHashFunc-Verify")
    assertBool(objVerify.ToVerify(), "SignBytesWithHashFunc-Verify")
}

func Test_SM2_SignBytes(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    uid := "N002462434000000"

    sm2key := "NBtl7WnuUtA2v5FaebEkU0/Jj1IodLGT6lQqwkzmd2E="
    sm2keyBytes, err2 := base64.StdEncoding.DecodeString(sm2key)

    assertError(err2, "sm2keyDecode")

    data := "123123"

    signedData := NewSM2().
        FromString(data).
        FromPrivateKeyBytes(sm2keyBytes).
        SignBytes([]byte(uid)).
        ToBase64String()

    assertNotEmpty(signedData, "sm2-SignBytes")
}

func Test_SM2_VerifyBytes(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertBool := cryptobin_test.AssertBoolT(t)

    uid := "N002462434000000"

    sm2key := "NBtl7WnuUtA2v5FaebEkU0/Jj1IodLGT6lQqwkzmd2E="
    sm2keyBytes, err2 := base64.StdEncoding.DecodeString(sm2key)

    assertError(err2, "sm2keyDecode")

    data := "123123"
    signedData := "S4vhrJoHXn98ByNw73CSOCqguYeuc4LrhsIHqkv/xA8Waw7YOLsfQzOKzxAjF0vyPKKSEQpq4zEgj9Mb/VL1pQ=="

    verify := NewSM2().
        FromBase64String(signedData).
        FromPrivateKeyBytes(sm2keyBytes).
        MakePublicKey().
        VerifyBytes([]byte(data), []byte(uid))

    assertError(verify.Error(), "sm2VerifyError")
    assertBool(verify.ToVerify(), "sm2-VerifyBytes")
}

func Test_SM2_Encrypt_C1C2C3(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    sm2key := "NBtl7WnuUtA2v5FaebEkU0/Jj1IodLGT6lQqwkzmd2E="
    sm2keyBytes, err2 := base64.StdEncoding.DecodeString(sm2key)

    assertError(err2, "Encrypt_C1C2C3-sm2keyDecode")

    data := "test-pass"

    sm2 := NewSM2()

    en := sm2.
        FromString(data).
        FromPrivateKeyBytes(sm2keyBytes).
        MakePublicKey().
        SetMode("C1C2C3"). // C1C3C2 | C1C2C3
        Encrypt()
    enData := en.ToBase64String()

    assertError(en.Error(), "Encrypt_C1C2C3-Encrypt")
    assertNotEmpty(enData, "Encrypt_C1C2C3-Encrypt")

    de := sm2.
        FromBase64String(enData).
        FromPrivateKeyBytes(sm2keyBytes).
        SetMode("C1C2C3"). // C1C3C2 | C1C2C3
        Decrypt()
    deData := de.ToString()

    assertError(de.Error(), "Encrypt_C1C2C3-Decrypt")
    assertNotEmpty(deData, "Encrypt_C1C2C3-Decrypt")

    assertEqual(data, deData, "Encrypt_C1C2C3-Dedata")
}

func Test_SM2_Encrypt_C1C3C2(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    sm2key := "NBtl7WnuUtA2v5FaebEkU0/Jj1IodLGT6lQqwkzmd2E="
    sm2keyBytes, err2 := base64.StdEncoding.DecodeString(sm2key)

    assertError(err2, "Encrypt_C1C3C2-sm2keyDecode")

    data := "test-pass"

    sm2 := NewSM2()

    en := sm2.
        FromString(data).
        FromPrivateKeyBytes(sm2keyBytes).
        MakePublicKey().
        SetMode("C1C3C2"). // C1C3C2 | C1C2C3
        Encrypt()
    enData := en.ToBase64String()

    assertError(en.Error(), "Encrypt_C1C3C2-Encrypt")
    assertNotEmpty(enData, "Encrypt_C1C3C2-Encrypt")

    de := sm2.
        FromBase64String(enData).
        FromPrivateKeyBytes(sm2keyBytes).
        SetMode("C1C3C2"). // C1C3C2 | C1C2C3
        Decrypt()
    deData := de.ToString()

    assertError(de.Error(), "Encrypt_C1C3C2-Decrypt")
    assertNotEmpty(deData, "Encrypt_C1C3C2-Decrypt")

    assertEqual(data, deData, "Encrypt_C1C3C2-Dedata")
}

func Test_SM2_EncryptASN1_C1C2C3(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    sm2key := "NBtl7WnuUtA2v5FaebEkU0/Jj1IodLGT6lQqwkzmd2E="
    sm2keyBytes, err2 := base64.StdEncoding.DecodeString(sm2key)

    assertError(err2, "DecryptASN1_C1C2C3-sm2keyDecode")

    data := "test-pass"

    sm2 := NewSM2()

    en := sm2.
        FromString(data).
        FromPrivateKeyBytes(sm2keyBytes).
        MakePublicKey().
        SetMode("C1C2C3"). // C1C3C2 | C1C2C3
        EncryptASN1()
    enData := en.ToBase64String()

    assertError(en.Error(), "DecryptASN1_C1C2C3-Encrypt")
    assertNotEmpty(enData, "DecryptASN1_C1C2C3-Encrypt")

    de := sm2.
        FromBase64String(enData).
        FromPrivateKeyBytes(sm2keyBytes).
        SetMode("C1C2C3"). // C1C3C2 | C1C2C3
        DecryptASN1()
    deData := de.ToString()

    assertError(de.Error(), "DecryptASN1_C1C2C3-Decrypt")
    assertNotEmpty(deData, "DecryptASN1_C1C2C3-Decrypt")

    assertEqual(data, deData, "DecryptASN1_C1C2C3-Dedata")
}

func Test_SM2_EncryptASN1_C1C3C2(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    sm2key := "NBtl7WnuUtA2v5FaebEkU0/Jj1IodLGT6lQqwkzmd2E="
    sm2keyBytes, err2 := base64.StdEncoding.DecodeString(sm2key)

    assertError(err2, "DecryptASN1_C1C3C2-sm2keyDecode")

    data := "test-pass"

    sm2 := NewSM2()

    en := sm2.
        FromString(data).
        FromPrivateKeyBytes(sm2keyBytes).
        MakePublicKey().
        SetMode("C1C3C2"). // C1C3C2 | C1C2C3
        EncryptASN1()
    enData := en.ToBase64String()

    assertError(en.Error(), "DecryptASN1_C1C3C2-Encrypt")
    assertNotEmpty(enData, "DecryptASN1_C1C3C2-Encrypt")

    de := sm2.
        FromBase64String(enData).
        FromPrivateKeyBytes(sm2keyBytes).
        SetMode("C1C3C2"). // C1C3C2 | C1C2C3
        DecryptASN1()
    deData := de.ToString()

    assertError(de.Error(), "DecryptASN1_C1C3C2-Decrypt")
    assertNotEmpty(deData, "DecryptASN1_C1C3C2-Decrypt")

    assertEqual(data, deData, "DecryptASN1_C1C3C2-Dedata")
}

var (
    prikeyPKCS1 = `
-----BEGIN SM2 PRIVATE KEY-----
MHcCAQEEIAVunzkO+VYC1MFl3TfjjEHkc21eRBz+qRxbgEA6BP/FoAoGCCqBHM9V
AYItoUQDQgAEAnfcXztAc2zQ+uHuRlXuMohDdsncWxQFjrpxv5Ae3/PgH9vewt4A
oEvRqcwOBWtAXNDP6E74e5ocagfMUbq4hQ==
-----END SM2 PRIVATE KEY-----

    `
    pubkeyPKCS1 = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEAnfcXztAc2zQ+uHuRlXuMohDdsnc
WxQFjrpxv5Ae3/PgH9vewt4AoEvRqcwOBWtAXNDP6E74e5ocagfMUbq4hQ==
-----END PUBLIC KEY-----

    `
)

func Test_PKCS1Sign(t *testing.T) {
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    data := "test-pass"

    // 签名
    objSign := New().
        FromString(data).
        FromPKCS1PrivateKey([]byte(prikeyPKCS1)).
        Sign()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "PKCS1Sign-Sign")
    assertNotEmpty(signed, "PKCS1Sign-Sign")

    // 验证
    objVerify := New().
        FromBase64String(signed).
        FromPublicKey([]byte(pubkeyPKCS1)).
        Verify([]byte(data))

    assertError(objVerify.Error(), "PKCS1Sign-Verify")
    assertBool(objVerify.ToVerify(), "PKCS1Sign-Verify")
}

func Test_PKCS1Encrypt(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    data := "123tesfd!df"

    objEn := New().
        FromString(data).
        FromPublicKey([]byte(pubkeyPKCS1)).
        Encrypt()
    enData := objEn.ToBase64String()

    assertError(objEn.Error(), "PKCS1Encrypt-Encrypt")
    assertNotEmpty(enData, "PKCS1Encrypt-Encrypt")

    objDe := New().
        FromBase64String(enData).
        FromPKCS1PrivateKey([]byte(prikeyPKCS1)).
        Decrypt()
    deData := objDe.ToString()

    assertError(objDe.Error(), "PKCS1Encrypt-Decrypt")
    assertNotEmpty(deData, "PKCS1Encrypt-Decrypt")

    assertEqual(data, deData, "PKCS1Encrypt-Dedata")
}

var (
    testSM2PublicKeyX  = "a4b75c4c8c44d11687bdd93c0883e630c895234beb685910efbe27009ad911fa"
    testSM2PublicKeyY  = "d521f5e8249de7a405f254a9888cbb8e651fd60c50bd22bd182a4bc7d1261c94"
    testSM2PrivateKeyD = "0f495b5445eb59ddecf0626f5ca0041c550584f0189e89d95f8d4c52499ff838"
)

func Test_CreateKey(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    pub := New().
        FromPublicKeyXYString(testSM2PublicKeyX, testSM2PublicKeyY).
        CreatePublicKey()
    pubData := pub.ToKeyString()

    assertError(pub.Error(), "CreateKey-pub")
    assertNotEmpty(pubData, "CreateKey-pub")

    // ======

    pri := New().
        FromPrivateKeyString(testSM2PrivateKeyD).
        CreatePrivateKey()
    priData := pri.ToKeyString()

    assertError(pri.Error(), "CreateKey-pri")
    assertNotEmpty(priData, "CreateKey-pri")
}

var testPEMCiphers = []string{
    "DESCBC",
    "DESEDE3CBC",
    "AES128CBC",
    "AES192CBC",
    "AES256CBC",

    "DESCFB",
    "DESEDE3CFB",
    "AES128CFB",
    "AES192CFB",
    "AES256CFB",

    "DESOFB",
    "DESEDE3OFB",
    "AES128OFB",
    "AES192OFB",
    "AES256OFB",

    "DESCTR",
    "DESEDE3CTR",
    "AES128CTR",
    "AES192CTR",
    "AES256CTR",
}

func Test_CreatePKCS1PrivateKeyWithPassword(t *testing.T) {
    for _, cipher := range testPEMCiphers{
        test_CreatePKCS1PrivateKeyWithPassword(t, cipher)
    }
}

func test_CreatePKCS1PrivateKeyWithPassword(t *testing.T, cipher string) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    t.Run(cipher, func(t *testing.T) {
        pass := make([]byte, 12)
        _, err := rand.Read(pass)
        if err != nil {
            t.Fatal(err)
        }

        gen := New().GenerateKey()

        prikey := gen.GetPrivateKey()

        pri := gen.
            CreatePKCS1PrivateKeyWithPassword(string(pass), cipher).
            ToKeyString()

        assertError(gen.Error(), "Test_CreatePKCS1PrivateKeyWithPassword")
        assertNotEmpty(pri, "Test_CreatePKCS1PrivateKeyWithPassword-pri")

        newPrikey := New().
            FromPKCS1PrivateKeyWithPassword([]byte(pri), string(pass)).
            GetPrivateKey()

        assertNotEmpty(newPrikey, "Test_CreatePKCS1PrivateKeyWithPassword-newPrikey")

        assertEqual(newPrikey, prikey, "Test_CreatePKCS1PrivateKeyWithPassword")
    })
}

// 招商银行签名会因为业务不同用的签名方法也会不同，签名方法默认有 SignBytes 和 SignASN1 两种，可根据招商银行给的 demo 选择对应的方法使用
func Test_ZhaoshangBank_Check(t *testing.T) {
    assertBool := cryptobin_test.AssertBoolT(t)

    // sm2 签名【招商银行】，
    sm2key := "NBtl7WnuUtA2v5FaebEkU0/Jj1IodLGT6lQqwkzmd2E="
    sm2keyBytes, _ := base64.StdEncoding.DecodeString(sm2key)
    sm2data := `{"request":{"body":{"TEST":"中文","TEST2":"!@#$%^&*()","TEST3":12345,"TEST4":[{"arrItem1":"qaz","arrItem2":123,"arrItem3":true,"arrItem4":"中文"}],"buscod":"N02030"},"head":{"funcode":"DCLISMOD","userid":"N003261207"}},"signature":{"sigdat":"__signature_sigdat__"}}`
    sm2userid := "N0032612070000000000000000"
    sm2userid = sm2userid[0:16]
    sm2Sign := New().
        FromString(sm2data).
        FromPrivateKeyBytes(sm2keyBytes).
        SignBytes([]byte(sm2userid)).
        // SignASN1([]byte(sm2userid)).
        ToBase64String()

    // sm2 验证【招商银行】
    sm2Verify := New().
        FromBase64String(sm2Sign).
        FromPrivateKeyBytes(sm2keyBytes).
        MakePublicKey().
        VerifyBytes([]byte(sm2data), []byte(sm2userid)).
        // VerifyASN1([]byte(sm2data), []byte(sm2userid)).
        ToVerify()

    assertBool(sm2Verify, "ZhaoshangBank_Check")
}

func Test_ZhaoshangBank_Sign(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    // 私钥明文
    sm2prikey := "NBtl7WnuUtA2v5FaebEkU0/Jj1IodLGT6lQqwkzmd2E="
    sm2prikeyBytes, _ := base64.StdEncoding.DecodeString(sm2prikey)
    sm2data := `{"request":{"body":{"TEST":"中文","TEST2":"!@#$%^&*()","TEST3":12345,"TEST4":[{"arrItem1":"qaz","arrItem2":123,"arrItem3":true,"arrItem4":"中文"}],"buscod":"N02030"},"head":{"funcode":"DCLISMOD","userid":"N003261207"}},"signature":{"sigdat":"__signature_sigdat__"}}`
    sm2userid := "N0032612070000000000000000"
    sm2userid = sm2userid[0:16]

    // sm2 签名【招商银行】，
    sm2Sign := New().
        FromString(sm2data).
        FromPrivateKeyBytes(sm2prikeyBytes).
        SignBytes([]byte(sm2userid)).
        // SignASN1([]byte(sm2userid)).
        ToBase64String()

    assertNotEmpty(sm2Sign, "ZhaoshangBank_Sign")
}

func Test_ZhaoshangBank_Sign2(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    // 私钥明文,16进制
    sm2prikey := "341b65ed69ee52d036bf915a79b124534fc98f522874b193ea542ac24ce67761"
    sm2data := `{"request":{"body":{"TEST":"中文","TEST2":"!@#$%^&*()","TEST3":12345,"TEST4":[{"arrItem1":"qaz","arrItem2":123,"arrItem3":true,"arrItem4":"中文"}],"buscod":"N02030"},"head":{"funcode":"DCLISMOD","userid":"N003261207"}},"signature":{"sigdat":"__signature_sigdat__"}}`
    sm2userid := "N0032612070000000000000000"
    sm2userid = sm2userid[0:16]

    // sm2 签名【招商银行】，
    sm2Sign := New().
        FromString(sm2data).
        FromPrivateKeyString(sm2prikey).
        SignBytes([]byte(sm2userid)).
        // SignASN1([]byte(sm2userid)).
        ToBase64String()

    assertNotEmpty(sm2Sign, "ZhaoshangBank_Sign")
}

func Test_ZhaoshangBank_Verify(t *testing.T) {
    assertBool := cryptobin_test.AssertBoolT(t)

    // 未压缩公钥明文,16进制
    sm2pubkey := "046374f8947b208b3f28a2dfaec78510f858bc1bad37f038b95903975c9636beb859653fb145727d02d65cd68f202abc2ff93eecea477b1dc81f4f650621b89e9d"
    sm2data := `{"request":{"body":{"TEST":"中文","TEST2":"!@#$%^&*()","TEST3":12345,"TEST4":[{"arrItem1":"qaz","arrItem2":123,"arrItem3":true,"arrItem4":"中文"}],"buscod":"N02030"},"head":{"funcode":"DCLISMOD","userid":"N003261207"}},"signature":{"sigdat":"__signature_sigdat__"}}`
    sm2userid := "N0032612070000000000000000"
    sm2userid = sm2userid[0:16]

    sm2signdata := "CDAYcxm3jM+65XKtFNii0tKrTmEbfNdR/Q/BtuQFzm5+luEf2nAhkjYTS2ygPjodpuAkarsNqjIhCZ6+xD4WKA=="

    // sm2 验证【招商银行】
    sm2Verify := New().
        FromBase64String(sm2signdata).
        FromPublicKeyUncompressString(sm2pubkey).
        VerifyBytes([]byte(sm2data), []byte(sm2userid)).
        // VerifyASN1([]byte(sm2data), []byte(sm2userid)).
        ToVerify()

    assertBool(sm2Verify, "ZhaoshangBank_Verify")
}

func Test_ZhaoshangBank_Verify2(t *testing.T) {
    assertBool := cryptobin_test.AssertBoolT(t)

    // 压缩公钥明文,16进制
    sm2pubkey := "036374f8947b208b3f28a2dfaec78510f858bc1bad37f038b95903975c9636beb8"
    sm2data := `{"request":{"body":{"TEST":"中文","TEST2":"!@#$%^&*()","TEST3":12345,"TEST4":[{"arrItem1":"qaz","arrItem2":123,"arrItem3":true,"arrItem4":"中文"}],"buscod":"N02030"},"head":{"funcode":"DCLISMOD","userid":"N003261207"}},"signature":{"sigdat":"__signature_sigdat__"}}`
    sm2userid := "N0032612070000000000000000"
    sm2userid = sm2userid[0:16]

    sm2signdata := "37fe1dd7697634612b8ec58e59c757b180c7a1262812766e84674e28f601f58a3748ec1bfe23702693d1ec160b116d66ffbddeb6529872fb2c311fd2e0ab5335"

    // sm2 验证【招商银行】
    sm2Verify := New().
        FromHexString(sm2signdata).
        FromPublicKeyCompressString(sm2pubkey).
        VerifyBytes([]byte(sm2data), []byte(sm2userid)).
        // VerifyASN1([]byte(sm2data), []byte(sm2userid)).
        ToVerify()

    assertBool(sm2Verify, "ZhaoshangBank_Verify")
}

func Test_PKCS1SignWithHash(t *testing.T) {
    test_PKCS1SignWithHash(t, "MD2")
    test_PKCS1SignWithHash(t, "MD4")
    test_PKCS1SignWithHash(t, "MD5")
    test_PKCS1SignWithHash(t, "SHA1")
    test_PKCS1SignWithHash(t, "SHA224")
    test_PKCS1SignWithHash(t, "SHA256")
    test_PKCS1SignWithHash(t, "SHA384")
    test_PKCS1SignWithHash(t, "SHA512")
    test_PKCS1SignWithHash(t, "RIPEMD160")
    test_PKCS1SignWithHash(t, "SHA3_224")
    test_PKCS1SignWithHash(t, "SHA3_256")
    test_PKCS1SignWithHash(t, "SHA3_384")
    test_PKCS1SignWithHash(t, "SHA3_512")
    test_PKCS1SignWithHash(t, "SHA512_224")
    test_PKCS1SignWithHash(t, "SHA512_256")
    test_PKCS1SignWithHash(t, "BLAKE2s_256")
    test_PKCS1SignWithHash(t, "BLAKE2b_256")
    test_PKCS1SignWithHash(t, "BLAKE2b_384")
    test_PKCS1SignWithHash(t, "BLAKE2b_512")
    test_PKCS1SignWithHash(t, "SM3")
}

func test_PKCS1SignWithHash(t *testing.T, hash string) {
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"

    t.Run("PKCS1SignWithHash " + hash, func(t *testing.T) {
        // 签名
        objSign := New().
            FromString(data).
            FromPKCS1PrivateKey([]byte(prikeyPKCS1)).
            SetSignHash(hash).
            Sign()
        signed := objSign.ToBase64String()

        assertError(objSign.Error(), "PKCS1SignWithHash-Sign")
        assertNotEmpty(signed, "PKCS1SignWithHash-Sign")

        // 验证
        objVerify := New().
            FromBase64String(signed).
            FromPublicKey([]byte(pubkeyPKCS1)).
            SetSignHash(hash).
            Verify([]byte(data))

        assertError(objVerify.Error(), "PKCS1SignWithHash-Verify")
        assertBool(objVerify.ToVerify(), "PKCS1SignWithHash-Verify")
    })
}

func Test_PKCS1SignWithHashFunc(t *testing.T) {
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    data := "test-pass"

    // 签名
    objSign := New().
        FromString(data).
        FromPKCS1PrivateKey([]byte(prikeyPKCS1)).
        WithSignHash(md5.New).
        Sign()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "PKCS1SignWithHashFunc-Sign")
    assertNotEmpty(signed, "PKCS1SignWithHashFunc-Sign")

    // 验证
    objVerify := New().
        FromBase64String(signed).
        FromPublicKey([]byte(pubkeyPKCS1)).
        WithSignHash(md5.New).
        Verify([]byte(data))

    assertError(objVerify.Error(), "PKCS1SignWithHashFunc-Verify")
    assertBool(objVerify.ToVerify(), "PKCS1SignWithHashFunc-Verify")
}

func Test_PKCS1SignASN1WithHashFunc(t *testing.T) {
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    data := "test-pass"
    uid := []byte("N003261207000000")

    // 签名
    objSign := New().
        FromString(data).
        FromPKCS1PrivateKey([]byte(prikeyPKCS1)).
        WithSignHash(md5.New).
        SignASN1(uid)
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "PKCS1SignWithHashFunc-Sign")
    assertNotEmpty(signed, "PKCS1SignWithHashFunc-Sign")

    // 验证
    objVerify := New().
        FromBase64String(signed).
        FromPublicKey([]byte(pubkeyPKCS1)).
        WithSignHash(md5.New).
        VerifyASN1([]byte(data), uid)

    assertError(objVerify.Error(), "PKCS1SignWithHashFunc-Verify")
    assertBool(objVerify.ToVerify(), "PKCS1SignWithHashFunc-Verify")
}

func Test_PKCS1SignBytesWithHashFunc(t *testing.T) {
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    data := "test-pass"
    uid := []byte("N003261207000000")

    // 签名
    objSign := New().
        FromString(data).
        FromPKCS1PrivateKey([]byte(prikeyPKCS1)).
        WithSignHash(md5.New).
        SignBytes(uid)
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "PKCS1SignWithHashFunc-Sign")
    assertNotEmpty(signed, "PKCS1SignWithHashFunc-Sign")

    // 验证
    objVerify := New().
        FromBase64String(signed).
        FromPublicKey([]byte(pubkeyPKCS1)).
        WithSignHash(md5.New).
        VerifyBytes([]byte(data), uid)

    assertError(objVerify.Error(), "PKCS1SignWithHashFunc-Verify")
    assertBool(objVerify.ToVerify(), "PKCS1SignWithHashFunc-Verify")
}

func Test_PKCS1SignBytesWithHashFunc_Fail(t *testing.T) {
    assertNotBool := cryptobin_test.AssertNotBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    data := "test-pass"
    uid := []byte("N003261207000000")

    // 签名
    objSign := New().
        FromString(data).
        FromPKCS1PrivateKey([]byte(prikeyPKCS1)).
        WithSignHash(md5.New).
        SignBytes(uid)
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "PKCS1SignWithHashFunc_Fail-Sign")
    assertNotEmpty(signed, "PKCS1SignWithHashFunc_Fail-Sign")

    sm2signdata := "123Ycxm312365XKtFNii0tKrTmEbfNdR/Q/BtuQFzm5+luEf2nAhkjYTS2ygPjodpuAkarsNqjIhCZ6+xD4WKA=="

    // 验证
    objVerify := New().
        FromBase64String(sm2signdata).
        FromPublicKey([]byte(pubkeyPKCS1)).
        WithSignHash(md5.New).
        VerifyBytes([]byte(data), uid)

    assertError(objVerify.Error(), "PKCS1SignWithHashFunc_Fail-Verify")
    assertNotBool(objVerify.ToVerify(), "PKCS1SignWithHashFunc_Fail-Verify")
}

// 测试 bc-java 库加密的数据解密
func Test_DecryptWithBCJavaEndata(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    // 明文： AH04DAEB01 对应16进制字串 41483034444145423031
    check := "AH04DAEB01"

    enData := "BB1925F51B39F7CB725783D4C5F62513F4763D60D4764D4B553C477491811009D221C1EBD33FF3FBA71CC082C350609C054D37E1CF6DC480B8FEF0970AE6D91C622A5759E15ABB3F663D4775B6A6B8E439368FC6D787B47C199A2F0A779F4FC4AFAB37B72790701DB561"
    prikey := "448152D77F06A39368BE3228C1CE8B6623B934359AB77D733768515259A80BD6"

    enDataBytes, _ := hex.DecodeString(enData)
    enDataBytes = append([]byte{byte(4)}, enDataBytes...)

    de := New().
        FromBytes(enDataBytes).
        FromPrivateKeyString(prikey).
        SetMode("C1C2C3").
        Decrypt()
    deData := de.ToString()

    assertError(de.Error(), "DecryptWithBCJavaEndata-Decrypt")
    assertNotEmpty(deData, "DecryptWithBCJavaEndata-Decrypt")

    assertEqual(deData, check, "DecryptWithBCJavaEndata-Dedata")
}
