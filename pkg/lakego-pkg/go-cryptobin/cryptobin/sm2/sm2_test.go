package sm2

import (
    "errors"
    "testing"
    "strings"
    "crypto/md5"
    "crypto/rand"
    "encoding/hex"
    "encoding/base64"

    "github.com/deatil/go-cryptobin/tool/hash"
    "github.com/deatil/go-cryptobin/gm/sm2"
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
        WithUID(uid).
        SignBytes()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "SignBytesWithHashFunc-Sign")
    assertNotEmpty(signed, "SignBytesWithHashFunc-Sign")

    // 验证
    objVerify := gen.
        FromBase64String(signed).
        WithSignHash(md5.New).
        WithUID(uid).
        VerifyBytes([]byte(data))

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
        WithUID([]byte(uid)).
        SignBytes().
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
        WithUID([]byte(uid)).
        VerifyBytes([]byte(data))

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

// 招商银行签名会因为业务不同用的签名方法也会不同，
// 签名方法默认有 SignBytes 和 SignASN1 两种，
// 可根据招商银行给的 demo 选择对应的方法使用
// SignBytes 为签名数据明文拼接
// SignASN1 为签名数据做 ASN.1 编码
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
        WithUID([]byte(sm2userid)).
        SignBytes().
        // SignASN1().
        ToBase64String()

    // sm2 验证【招商银行】
    sm2Verify := New().
        FromBase64String(sm2Sign).
        FromPrivateKeyBytes(sm2keyBytes).
        MakePublicKey().
        WithUID([]byte(sm2userid)).
        VerifyBytes([]byte(sm2data)).
        // VerifyASN1([]byte(sm2data)).
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
        WithUID([]byte(sm2userid)).
        SignBytes().
        // SignASN1().
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
        WithUID([]byte(sm2userid)).
        SignBytes().
        // SignASN1().
        ToBase64String()

    assertNotEmpty(sm2Sign, "ZhaoshangBank_Sign")
}

func Test_ZhaoshangBank_Verify(t *testing.T) {
    assertBool := cryptobin_test.AssertBoolT(t)

    // 未压缩公钥明文, 16进制
    sm2pubkey := "046374f8947b208b3f28a2dfaec78510f858bc1bad37f038b95903975c9636beb859653fb145727d02d65cd68f202abc2ff93eecea477b1dc81f4f650621b89e9d"
    sm2data := `{"request":{"body":{"TEST":"中文","TEST2":"!@#$%^&*()","TEST3":12345,"TEST4":[{"arrItem1":"qaz","arrItem2":123,"arrItem3":true,"arrItem4":"中文"}],"buscod":"N02030"},"head":{"funcode":"DCLISMOD","userid":"N003261207"}},"signature":{"sigdat":"__signature_sigdat__"}}`
    sm2userid := "N0032612070000000000000000"
    sm2userid = sm2userid[0:16]

    sm2signdata := "CDAYcxm3jM+65XKtFNii0tKrTmEbfNdR/Q/BtuQFzm5+luEf2nAhkjYTS2ygPjodpuAkarsNqjIhCZ6+xD4WKA=="

    // sm2 验证【招商银行】
    sm2Verify := New().
        FromBase64String(sm2signdata).
        FromPublicKeyUncompressString(sm2pubkey).
        WithUID([]byte(sm2userid)).
        VerifyBytes([]byte(sm2data)).
        // VerifyASN1([]byte(sm2data)).
        ToVerify()

    assertBool(sm2Verify, "Test_ZhaoshangBank_Verify")
}

func Test_ZhaoshangBank_Verify2(t *testing.T) {
    assertBool := cryptobin_test.AssertBoolT(t)

    // 压缩公钥明文, 16进制
    sm2pubkey := "036374f8947b208b3f28a2dfaec78510f858bc1bad37f038b95903975c9636beb8"
    sm2data := `{"request":{"body":{"TEST":"中文","TEST2":"!@#$%^&*()","TEST3":12345,"TEST4":[{"arrItem1":"qaz","arrItem2":123,"arrItem3":true,"arrItem4":"中文"}],"buscod":"N02030"},"head":{"funcode":"DCLISMOD","userid":"N003261207"}},"signature":{"sigdat":"__signature_sigdat__"}}`
    sm2userid := "N0032612070000000000000000"
    sm2userid = sm2userid[0:16]

    sm2signdata := "37fe1dd7697634612b8ec58e59c757b180c7a1262812766e84674e28f601f58a3748ec1bfe23702693d1ec160b116d66ffbddeb6529872fb2c311fd2e0ab5335"

    // sm2 验证【招商银行】
    sm2Verify := New().
        FromHexString(sm2signdata).
        FromPublicKeyCompressString(sm2pubkey).
        WithUID([]byte(sm2userid)).
        VerifyBytes([]byte(sm2data)).
        // VerifyASN1([]byte(sm2data)).
        ToVerify()

    assertBool(sm2Verify, "Test_ZhaoshangBank_Verify2")
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
        WithUID(uid).
        SignASN1()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "PKCS1SignWithHashFunc-Sign")
    assertNotEmpty(signed, "PKCS1SignWithHashFunc-Sign")

    // 验证
    objVerify := New().
        FromBase64String(signed).
        FromPublicKey([]byte(pubkeyPKCS1)).
        WithSignHash(md5.New).
        WithUID(uid).
        VerifyASN1([]byte(data))

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
        WithUID(uid).
        SignBytes()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "PKCS1SignWithHashFunc-Sign")
    assertNotEmpty(signed, "PKCS1SignWithHashFunc-Sign")

    // 验证
    objVerify := New().
        FromBase64String(signed).
        FromPublicKey([]byte(pubkeyPKCS1)).
        WithSignHash(md5.New).
        WithUID(uid).
        VerifyBytes([]byte(data))

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
        WithUID(uid).
        SignBytes()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "PKCS1SignWithHashFunc_Fail-Sign")
    assertNotEmpty(signed, "PKCS1SignWithHashFunc_Fail-Sign")

    sm2signdata := "123Ycxm312365XKtFNii0tKrTmEbfNdR/Q/BtuQFzm5+luEf2nAhkjYTS2ygPjodpuAkarsNqjIhCZ6+xD4WKA=="

    // 验证
    objVerify := New().
        FromBase64String(sm2signdata).
        FromPublicKey([]byte(pubkeyPKCS1)).
        WithSignHash(md5.New).
        WithUID(uid).
        VerifyBytes([]byte(data))

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

func Test_With(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    privateKey, err := sm2.GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    publicKey := &privateKey.PublicKey

    mode := C1C3C2
    data := []byte("test-pass")
    parsedData := []byte("test-parsedData")
    uid := []byte("N003261207000000")

    hash, _ := hash.GetHash("MD5")

    verify := true
    errTest := []error{errors.New("test error")}

    obj := New().
        WithPrivateKey(privateKey).
        WithPublicKey(publicKey).
        WithMode(mode).
        WithData(data).
        WithParsedData(parsedData).
        WithSignHash(hash).
        WithUID(uid).
        WithVerify(verify).
        WithErrors(errTest)

    assertEqual(obj.privateKey, privateKey, "With privateKey")
    assertEqual(obj.publicKey, publicKey, "With publicKey")
    assertEqual(obj.mode, mode, "With mode")
    assertEqual(obj.data, data, "With data")
    assertEqual(obj.parsedData, parsedData, "With parsedData")
    assertNotEmpty(obj.signHash, "With signHash")
    assertEqual(obj.uid, uid, "With uid")
    assertEqual(obj.verify, verify, "With verify")
    assertEqual(obj.Errors, errTest, "With errTest")

    uid2 := "N0032612071111111"

    obj = obj.
        SetSignHash("SHA1").
        SetMode("C1C2C3").
        SetUID(uid2)

    assertEqual(obj.mode, C1C2C3, "Set mode")
    assertNotEmpty(obj.signHash, "Set signHash")
    assertEqual(obj.uid, []byte(uid2), "Set uid")
}

func Test_Get(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    privateKey, err := sm2.GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    publicKey := &privateKey.PublicKey

    mode := C1C3C2
    data := []byte("test-pass")
    parsedData := []byte("test-parsedData")
    uid := []byte("N003261207000000")

    keyData := []byte("test-keyData")

    verify := true
    errTest := []error{errors.New("test error")}

    obj := SM2{
        privateKey: privateKey,
        publicKey: publicKey,
        keyData: keyData,
        mode: mode,
        data: data,
        parsedData: parsedData,
        uid: uid,
        verify: verify,
        Errors: errTest,
    }

    assertEqual(obj.GetPrivateKey(), privateKey, "GetPrivateKey")
    assertEqual(obj.GetPublicKey(), publicKey, "GetPublicKey")
    assertEqual(obj.GetKeyData(), keyData, "GetKeyData")
    assertEqual(obj.GetMode(), mode, "GetMode")
    assertEqual(obj.GetData(), data, "GetData")
    assertEqual(obj.GetParsedData(), parsedData, "GetParsedData")
    assertEqual(obj.GetUID(), uid, "GetUID")
    assertEqual(obj.GetVerify(), verify, "GetVerify")
    assertEqual(obj.GetErrors(), errTest, "GetErrors")
}

func Test_SignSM3Digest_Check(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    uid := "sm2test@example.com"
    msg := "hi chappy"
    x := "110E7973206F68C19EE5F7328C036F26911C8C73B4E4F36AE3291097F8984FFC"
    r := "05890B9077B92E47B17A1FF42A814280E556AFD92B4A98B9670BF8B1A274C2FA"
    s := "E3ABBB8DB2B6ECD9B24ECCEA7F679FB9A4B1DB52F4AA985E443AD73237FA1993"

    sig, _ := hex.DecodeString(r+s)

    obj := New().
        FromBytes(sig).
        FromPrivateKeyString(x).
        MakePublicKey().
        SetUID(uid).
        VerifyBytes([]byte(msg))
    veri := obj.ToVerify()

    assertError(obj.Error(), "Test_SignSM3Digest_Check")
    assertEqual(veri, true, "Test_SignSM3Digest_Check")
}

func Test_SignSHA256Digest_Check(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    uid := "sm2test@example.com"
    msg := "hi chappy"
    x := "110E7973206F68C19EE5F7328C036F26911C8C73B4E4F36AE3291097F8984FFC"
    r := "94DA20EA69E4FC70692158BF3D30F87682A4B2F84DF4A4829A1EFC5D9C979D3F"
    s := "EE15AF8D455B728AB80E592FCB654BF5B05620B2F4D25749D263D5C01FAD365F"

    sig, _ := hex.DecodeString(r+s)

    obj := New().
        FromBytes(sig).
        FromPrivateKeyString(x).
        MakePublicKey().
        SetUID(uid).
        SetSignHash("SHA256").
        VerifyBytes([]byte(msg))
    veri := obj.ToVerify()

    assertError(obj.Error(), "Test_SignSHA256Digest_Check")
    assertEqual(veri, true, "Test_SignSHA256Digest_Check")
}

var testPrikey3 = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQga0uyz+bU40mfdM/QWwSLOAIw1teD
frvhqGWFAFT7r9uhRANCAATsU4K/XvtvANt0yF+eSabtX20tNXCMfaVMSmV7iq4gGxJKXppqIObD
ccNE4TCP1uA7VyFgARYRXKGzV/eMSx17
-----END PRIVATE KEY-----
`

func Test_EncryptHash_Check(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    check := "testtest123123"

    tests := []struct{
        priv string
        endata string
        hash string
        mode string // C1C3C2 | C1C2C3
        check string
    }{
        {
            priv: testPrikey3,
            endata: "BF4VK8u+cxAMoUBuc5S0yi1GISy6qYhMeep3As+I9MhOh42yuMLCbV7p+srwgZACcmC8CgsEN3wOaZAiVKSqIPxLN8gQFseZ/7B2uJ+RvCKaJK1QeG+iToaDO19BI02gO6r5KYkFGnv4TFaNDHUW",
            hash: "SM3",
            mode: "C1C3C2",
            check: check,
        },
        {
            priv: testPrikey3,
            endata: "BPSJaSfjaR5hy1mN6G5pVYXVbgzl0xo6YcCbxkrJgC91s2yLSBdDXcr+kJH6LTTCJ7wIb6M7xMn/lZslrzlGOsLV1uiFr9uHnI2p91GEbttKJ+8hE8Luiwb8gzB5DF4wDLee",
            hash: "SHA1",
            mode: "C1C3C2",
            check: check,
        },
        {
            priv: testPrikey3,
            endata: "BF7X/kRsh3N9YWdYKBlVBRZXwVO79IocLQS6a69B5Gch9bbZf8jjqZnVLPdC9Dh21/HqLNDd1tjuu8VnHJFyp3soUCgN94A9+BWt1Uy6+uZuQXFcZHfVqyw/7tXMKtDVEV2aKodne7Boc7RZ0bO4",
            hash: "SHA256",
            mode: "C1C3C2",
            check: check,
        },
        {
            priv: testPrikey3,
            endata: "BOnorWOFRDcSInLLTp9hDcydEg7Z2nUF2JbZ23SxnxzzsraiKUtPB9oTZezrBm3wRHgW0cRkOK9N0FP4CaCPThYeY/nz/nomkHIVyCc5cRZgI0IvPJevEjnGgq0Vu1k8X8LdX+5m3BA377y5jYJzVGZItXqW2Ns4Q/tIIDLZOPaEKGxkfcF2cykkhuggeyM=",
            hash: "SHA512",
            mode: "C1C3C2",
            check: check,
        },
    }

    for _, td := range tests {
        de := New().
            FromBase64String(td.endata).
            FromPrivateKey([]byte(td.priv)).
            SetSignHash(td.hash).
            SetMode(td.mode).
            Decrypt()
        deData := de.ToString()

        assertError(de.Error(), "Test_EncryptHash_Check-Decrypt-"+td.hash)
        assertEqual(deData, td.check, "Test_EncryptHash_Check-deData-"+td.hash)
    }

}

// 测试 bc-java 库加密的数据解密
func Test_DecryptWithBCJavaEndata2(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    java_prikey := "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQg6rgCft6jHsmv5YnpZaWrk7fQQY9R2VoWyJ9d87XSfv6gCgYIKoEcz1UBgi2hRANCAAQRvBC+7ApOlK7fKzDb/XBCw7CrWZkC8orgyKbBbGxZRwVbCYmjygAUF6no4c1/g2lsxc+LiDUGXcAv1gr7+fGq"
    java_pubkey := "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEEbwQvuwKTpSu3ysw2/1wQsOwq1mZAvKK4MimwWxsWUcFWwmJo8oAFBep6OHNf4NpbMXPi4g1Bl3AL9YK+/nxqg=="

    go_prikey := "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgUrsLxV86AjpYVYuIZdocV5v+1yHU+KO5U73If/Pe5fmgCgYIKoEcz1UBgi2hRANCAASpHt92CMRA92RyBfXQ1LzOPTjq1qOf/0Z7KVdyc/zmsbeCKmwaGQeXn9IU5R7khb5V8DQcl+n1kr5Z8DM1fIUW"
    go_pubkey := "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEqR7fdgjEQPdkcgX10NS8zj046tajn/9GeylXcnP85rG3gipsGhkHl5/SFOUe5IW+VfA0HJfp9ZK+WfAzNXyFFg=="

    java_prikeyBytes, _ := base64.StdEncoding.DecodeString(java_prikey)
    java_pubkeyBytes, _ := base64.StdEncoding.DecodeString(java_pubkey)

    go_prikeyBytes, _ := base64.StdEncoding.DecodeString(go_prikey)
    go_pubkeyBytes, _ := base64.StdEncoding.DecodeString(go_pubkey)

    // 原始数据
    oldData := "LoveLive!TypeMoon!Idoly-Pride！"

    java_enData := "BPkRkx6Wl4KlHajh+V5znPxxpAFkZhQlxXFlaJxd/wRPHqxvnEaR/NI2d6+pa7CKXVHoJQ1Z6bAsXYEDYnKVJyNeIqhqQxxrNGl5rURnL0kDdwGJiEGQ54FRprdMIY0YEIngqw7fkorKk+6SLiTSDjuAr//z+VK4JoA6jEvuIy1l"
    java_sign := "MEQCICAyzvt0lGp8TmErHdiQ4Ovkso0Ji8edFif04yhPuOY3AiBKeSzegV8Wh2KSHXt4AmXnoo8ELzF8PNLRgkzfbBhpmw=="

    java_enDataBytes, _ := base64.StdEncoding.DecodeString(java_enData)

    _ = go_prikeyBytes
    _ = go_pubkeyBytes
    _ = java_pubkeyBytes
    _ = java_enDataBytes

    de := FromBase64String(java_enData).
        FromPKCS8PrivateKeyDer(java_prikeyBytes).
        SetMode("C1C2C3").
        Decrypt()
    deData := de.ToString()

    assertError(de.Error(), "Test_DecryptWithBCJavaEndata2-Decrypt")
    assertNotEmpty(deData, "Test_DecryptWithBCJavaEndata2-Decrypt")

    assertEqual(deData, oldData, "Test_DecryptWithBCJavaEndata2-Dedata")

    // ==============

    obj := FromBase64String(java_sign).
        FromPublicKeyDer(go_pubkeyBytes).
        VerifyASN1(java_enDataBytes)
    veri := obj.ToVerify()

    assertError(obj.Error(), "Test_DecryptWithBCJavaEndata2")
    assertEqual(veri, true, "Test_DecryptWithBCJavaEndata2")
}

var testWeappPublicKey = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEKpbg7G/d0ReCOzaZk3O3SVkiFoRG
iFskXEzc2/gYrHvQQMcg5imja570cQ7y7bx1ezNA4bjHEPFtbhj8h/RKig==
-----END PUBLIC KEY-----
`

// https://developers.weixin.qq.com/miniprogram/dev/OpenApiDoc/getting_started/api_signature.html
// 在小程序管理后台开启api加密后，
// 开发者需要对原API的请求内容加密与签名，
// 同时API的回包内容需要开发者验签与解密。
// 微信小程序 SM2withSM3 验证
func Test_SignSM3Digest_Weapp_Check(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    uid := "8a98f6bba1415c0c4f6879bda6807861"

    req_data := `{"iv":"b3sjwc9yvUEGH45l","data":"fa8VugXI8UA2ugS646ZvuX0wo4qn0Eua2J9jtwACQXeVys3hP/fZDcZC4eEF9es/z/Zx6GM2piwoHKPmPbwzfNXWc/rUH/USFoKo6OBSiR8bb6QgkzYzYL9KsawMr8X/z6y8o3UzE5w65nfTySQFSpEVplD5S+SwQrLi3I2nUwS5N3SoJYsf8BHVfsYLBI9h1NocLgfjjyPYmeKsQ/t1muVWlV2Z75VbqFhM+ECgHpEvcWPDeUN5ZhZ6C/0=","authtag":"cDZY4giOZgf73/CvObhypQ=="}`
    data := "https://api.weixin.qq.com/wxa/getuserriskrank\nwxba6223c06417af7b\n1692932963\n" + req_data
    signData := "MEUCIQC++rC5Zv+84JtUZx+2w/QzpIH3KyRsMCFPcSZlxD9gCQIgGfBRLUc0S13vSGmBPS5zyNfi1IEibxlaL0lPvV+Ap20="

    obj := New().
        FromBase64String(signData).
        FromPublicKey([]byte(testWeappPublicKey)).
        SetUID(uid).
        VerifyASN1([]byte(data))
    veri := obj.ToVerify()

    assertError(obj.Error(), "Test_SignSM3Digest_Weapp_Check")
    assertEqual(veri, true, "Test_SignSM3Digest_Weapp_Check")
}

var testEnPrivateKey22 = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILVZdvMydZGiSaiwYU0u9sASEi2i3WwYE38MZjRvpGgroAoGCCqBHM9V
AYItoUQDQgAEe6Nc0BJgsyrcKmbpYDox7iX3adD165XA0NnNmDkk/XmJ5xK/Lfnm
MSTaI4vA+UGpGw5kqhKAbFzHJyKjgFz2sQ==
-----END EC PRIVATE KEY-----
`
var testSignPublicKey22 = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEd5tZ/XlQgV9AbJbU5JuzZimcK/LC
OX+xNwdI1XHHkIGl3W0VBmGRBK3VxkBSvp8tsGkZsxEmA7ngXyECzrDiuA==
-----END PUBLIC KEY-----
`

func Test_SignAndDecrypt_Check22(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    encrypted := `MH8CIQC5vLQm7+4JYg5MD39ViKgeuHnAN3BZpzD36pHYOada9QIgLiKsD1GLVRW5bW7sanplYCi+
+e6wuarVffKZDnTTWCkEIMcgRSAXgDLhEJDtmed4LCPdRitNjd3ywVpfi12b5rchBBaObgYaK/8s
h6D5seFQFqp7B246d9lr`
    signData := `MEYCIQDr7Vgvt0pfMddIa94dxvc3IkpEvkMhm07A0NEKASHcWwIhANPaZzmsV5m4I3TKkWecCcV1
jGAJaWDORkhDVOkYH2Rt`

    uid := base64.StdEncoding.EncodeToString([]byte("qinnong"))

    obj := New().
        FromBase64String(signData).
        FromPublicKey([]byte(testSignPublicKey22)).
        SetUID(uid).
        VerifyASN1([]byte(encrypted))
    veri := obj.ToVerify()

    assertError(obj.Error(), "Test_SignAndDecrypt_Check22")
    assertEqual(veri, true, "Test_SignAndDecrypt_Check22")

    // ===========

    data, _ := base64.StdEncoding.DecodeString(encrypted)

    de := New().
        FromBytes(data).
        FromPKCS1PrivateKey([]byte(testEnPrivateKey22)).
        SetMode("C1C3C2").
        DecryptASN1()
    deData := de.ToString()

    check := `["{\"data\":\"qwe\"}"]`

    assertError(de.Error(), "Test_SignAndDecrypt_Check22-DecryptASN1")
    assertEqual(deData, check, "Test_SignAndDecrypt_Check22-DecryptASN1")
}

func Test_SM2_EncryptECB(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    sm2key := "NBtl7WnuUtA2v5FaebEkU0/Jj1IodLGT6lQqwkzmd2E="
    sm2keyBytes, err2 := base64.StdEncoding.DecodeString(sm2key)

    assertError(err2, "Test_SM2_EncryptECB-sm2keyDecode")

    data := strings.Repeat("test-pass", 1 << 12)

    sm2 := NewSM2()

    en := sm2.
        FromString(data).
        FromPrivateKeyBytes(sm2keyBytes).
        MakePublicKey().
        EncryptECB()
    enData := en.ToBase64String()

    assertError(en.Error(), "Test_SM2_EncryptECB-Encrypt")
    assertNotEmpty(enData, "Test_SM2_EncryptECB-Encrypt")

    de := sm2.
        FromBase64String(enData).
        FromPrivateKeyBytes(sm2keyBytes).
        DecryptECB()
    deData := de.ToString()

    assertError(de.Error(), "Test_SM2_EncryptECB-Decrypt")
    assertNotEmpty(deData, "Test_SM2_EncryptECB-Decrypt")

    assertEqual(deData, data, "Test_SM2_EncryptECB-Dedata")
}

func Test_SM2_EncryptASN1ECB(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    sm2key := "NBtl7WnuUtA2v5FaebEkU0/Jj1IodLGT6lQqwkzmd2E="
    sm2keyBytes, err2 := base64.StdEncoding.DecodeString(sm2key)

    assertError(err2, "Test_SM2_EncryptASN1ECB-sm2keyDecode")

    data := strings.Repeat("test-pass", 1 << 12)

    sm2 := NewSM2()

    en := sm2.
        FromString(data).
        FromPrivateKeyBytes(sm2keyBytes).
        MakePublicKey().
        EncryptASN1ECB()
    enData := en.ToBase64String()

    assertError(en.Error(), "Test_SM2_EncryptASN1ECB-Encrypt")
    assertNotEmpty(enData, "Test_SM2_EncryptASN1ECB-Encrypt")

    de := sm2.
        FromBase64String(enData).
        FromPrivateKeyBytes(sm2keyBytes).
        DecryptASN1ECB()
    deData := de.ToString()

    assertError(de.Error(), "Test_SM2_EncryptASN1ECB-Decrypt")
    assertNotEmpty(deData, "Test_SM2_EncryptASN1ECB-Decrypt")

    assertEqual(deData, data, "Test_SM2_EncryptASN1ECB-Dedata")
}

var testPublicKeyForGet = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEd5tZ/XlQgV9AbJbU5JuzZimcK/LC
OX+xNwdI1XHHkIGl3W0VBmGRBK3VxkBSvp8tsGkZsxEmA7ngXyECzrDiuA==
-----END PUBLIC KEY-----
`
var testPrivateKeyForGet = `
-----BEGIN SM2 PRIVATE KEY-----
MHcCAQEEIAVunzkO+VYC1MFl3TfjjEHkc21eRBz+qRxbgEA6BP/FoAoGCCqBHM9V
AYItoUQDQgAEAnfcXztAc2zQ+uHuRlXuMohDdsncWxQFjrpxv5Ae3/PgH9vewt4A
oEvRqcwOBWtAXNDP6E74e5ocagfMUbq4hQ==
-----END SM2 PRIVATE KEY-----
`

func Test_PublicKeyForGet_Check(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    xStringCheck := `779b59fd7950815f406c96d4e49bb366299c2bf2c2397fb1370748d571c79081`
    yStringCheck := `a5dd6d1506619104add5c64052be9f2db06919b3112603b9e05f2102ceb0e2b8`
    xyStringCheck := `779b59fd7950815f406c96d4e49bb366299c2bf2c2397fb1370748d571c79081a5dd6d1506619104add5c64052be9f2db06919b3112603b9e05f2102ceb0e2b8`
    xyUncompressStringCheck := `04779b59fd7950815f406c96d4e49bb366299c2bf2c2397fb1370748d571c79081a5dd6d1506619104add5c64052be9f2db06919b3112603b9e05f2102ceb0e2b8`
    dStringCheck := `056e9f390ef95602d4c165dd37e38c41e4736d5e441cfea91c5b80403a04ffc5`

    xString := New().
        FromPublicKey([]byte(testPublicKeyForGet)).
        GetPublicKeyXString()

    yString := New().
        FromPublicKey([]byte(testPublicKeyForGet)).
        GetPublicKeyYString()

    xyString := New().
        FromPublicKey([]byte(testPublicKeyForGet)).
        GetPublicKeyXYString()

    xyUncompressString := New().
        FromPublicKey([]byte(testPublicKeyForGet)).
        GetPublicKeyUncompressString()

    dString := New().
        FromPrivateKey([]byte(testPrivateKeyForGet)).
        GetPrivateKeyDString()

    assertEqual(xString, xStringCheck, "Test_PublicKeyForGet_x_Check")
    assertEqual(yString, yStringCheck, "Test_PublicKeyForGet_y_Check")
    assertEqual(xyString, xyStringCheck, "Test_PublicKeyForGet_xy_Check")
    assertEqual(xyUncompressString, xyUncompressStringCheck, "Test_PublicKeyForGet_xyu_Check")
    assertEqual(dString, dStringCheck, "Test_PublicKeyForGet_d_Check")
}

func Test_EncodingType(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    var sm2 SM2

    sm2 = NewSM2().WithEncoding(EncodingASN1)
    assertEqual(sm2.encoding, EncodingASN1, "EncodingASN1 1")

    sm2 = NewSM2().WithEncodingASN1()
    assertEqual(sm2.encoding, EncodingASN1, "EncodingASN1")

    sm2 = NewSM2().WithEncodingBytes()
    assertEqual(sm2.encoding, EncodingBytes, "EncodingBytes")

    sm2 = SM2{
        encoding: EncodingASN1,
    }
    assertEqual(sm2.GetEncoding(), EncodingASN1, "new EncodingASN1")

    sm2 = SM2{
        encoding: EncodingBytes,
    }
    assertEqual(sm2.GetEncoding(), EncodingBytes, "new EncodingBytes")
}

func Test_PKCS1SignWithEncoding(t *testing.T) {
    t.Run("EncodingASN1", func(t *testing.T) {
        test_PKCS1SignWithEncoding(t, EncodingASN1)
    })
    t.Run("EncodingBytes", func(t *testing.T) {
        test_PKCS1SignWithEncoding(t, EncodingBytes)
    })
}

func test_PKCS1SignWithEncoding(t *testing.T, encoding EncodingType) {
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"

    // 签名
    objSign := New().
        FromString(data).
        FromPKCS1PrivateKey([]byte(prikeyPKCS1)).
        WithEncoding(encoding).
        Sign()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "PKCS1SignWithEncoding-Sign")
    assertNotEmpty(signed, "PKCS1SignWithEncoding-Sign")

    // 验证
    objVerify := New().
        FromBase64String(signed).
        FromPublicKey([]byte(pubkeyPKCS1)).
        WithEncoding(encoding).
        Verify([]byte(data))

    assertError(objVerify.Error(), "PKCS1SignWithEncoding-Verify")
    assertBool(objVerify.ToVerify(), "PKCS1SignWithEncoding-Verify")
}

func Test_SM2_EncryptWithEncoding(t *testing.T) {
    t.Run("EncodingASN1", func(t *testing.T) {
        test_SM2_EncryptWithEncoding(t, EncodingASN1)
    })
    t.Run("EncodingBytes", func(t *testing.T) {
        test_SM2_EncryptWithEncoding(t, EncodingBytes)
    })
}

func test_SM2_EncryptWithEncoding(t *testing.T, encoding EncodingType) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    sm2key := "NBtl7WnuUtA2v5FaebEkU0/Jj1IodLGT6lQqwkzmd2E="
    sm2keyBytes, err2 := base64.StdEncoding.DecodeString(sm2key)

    assertError(err2, "test_SM2_EncryptWithEncoding-sm2keyDecode")

    data := "test-pass"

    sm2 := NewSM2()

    en := sm2.
        FromString(data).
        FromPrivateKeyBytes(sm2keyBytes).
        MakePublicKey().
        WithEncoding(encoding).
        Encrypt()
    enData := en.ToBase64String()

    assertError(en.Error(), "test_SM2_EncryptWithEncoding-Encrypt")
    assertNotEmpty(enData, "test_SM2_EncryptWithEncoding-Encrypt")

    de := sm2.
        FromBase64String(enData).
        FromPrivateKeyBytes(sm2keyBytes).
        WithEncoding(encoding).
        Decrypt()
    deData := de.ToString()

    assertError(de.Error(), "test_SM2_EncryptWithEncoding-Decrypt")
    assertNotEmpty(deData, "test_SM2_EncryptWithEncoding-Decrypt")

    assertEqual(deData, data, "test_SM2_EncryptWithEncoding-Dedata")
}

func Test_SM2_EncryptECBWithEncoding(t *testing.T) {
    t.Run("EncodingASN1", func(t *testing.T) {
        test_SM2_EncryptECBWithEncoding(t, EncodingASN1)
    })
    t.Run("EncodingBytes", func(t *testing.T) {
        test_SM2_EncryptECBWithEncoding(t, EncodingBytes)
    })
}

func test_SM2_EncryptECBWithEncoding(t *testing.T, encoding EncodingType) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    sm2key := "NBtl7WnuUtA2v5FaebEkU0/Jj1IodLGT6lQqwkzmd2E="
    sm2keyBytes, err2 := base64.StdEncoding.DecodeString(sm2key)

    assertError(err2, "test_SM2_EncryptECBWithEncoding-sm2keyDecode")

    data := "test-pass"

    sm2 := NewSM2()

    en := sm2.
        FromString(data).
        FromPrivateKeyBytes(sm2keyBytes).
        MakePublicKey().
        WithEncoding(encoding).
        EncryptECB()
    enData := en.ToBase64String()

    assertError(en.Error(), "test_SM2_EncryptECBWithEncoding-Encrypt")
    assertNotEmpty(enData, "test_SM2_EncryptECBWithEncoding-Encrypt")

    de := sm2.
        FromBase64String(enData).
        FromPrivateKeyBytes(sm2keyBytes).
        WithEncoding(encoding).
        DecryptECB()
    deData := de.ToString()

    assertError(de.Error(), "test_SM2_EncryptECBWithEncoding-Decrypt")
    assertNotEmpty(deData, "test_SM2_EncryptECBWithEncoding-Decrypt")

    assertEqual(deData, data, "test_SM2_EncryptECBWithEncoding-Dedata")
}

func Test_PKCS1SignWithEncoding_Two_Check(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertNotEqual := cryptobin_test.AssertNotEqualT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"

    // 签名
    objSign := New().
        FromString(data).
        FromPKCS1PrivateKey([]byte(prikeyPKCS1)).
        WithEncoding(EncodingASN1).
        Sign()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "Test_SignWithEncoding_Two_Check-Sign")
    assertNotEmpty(signed, "Test_SignWithEncoding_Two_Check-Sign")

    // 签名
    objSign2 := New().
        FromString(data).
        FromPKCS1PrivateKey([]byte(prikeyPKCS1)).
        WithEncoding(EncodingBytes).
        Sign()
    signed2 := objSign2.ToBase64String()

    assertError(objSign2.Error(), "Test_SignWithEncoding_Two_Check-Sign")
    assertNotEmpty(signed2, "Test_SignWithEncoding_Two_Check-Sign")

    assertNotEqual(signed2, signed, "Test_SignWithEncoding_Two_Check")
}
