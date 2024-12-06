package elgamal

import (
    "testing"
    "crypto/rand"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var (
    prikeyXML = `
<ElGamalKeyValue>
    <P>9W35RbKvFgfHndG9wVvFDMDw86BClpDk6kdeGr1ygLc=</P>
    <G>vG406oGr5OqG0mMOtq5wWo/aGWWE8EPiPl09/I+ySxs=</G>
    <Y>120jHKCdPWjLGrqH3HiCZ2GezWyEjfEIPBMhULymfzM=</Y>
    <X>BjtroR34tS5cvF5YNJaxmOjGDas43wKFunHCYS4P6CQ=</X>
</ElGamalKeyValue>
    `
    pubkeyXML = `
<ElGamalKeyValue>
    <P>9W35RbKvFgfHndG9wVvFDMDw86BClpDk6kdeGr1ygLc=</P>
    <G>vG406oGr5OqG0mMOtq5wWo/aGWWE8EPiPl09/I+ySxs=</G>
    <Y>120jHKCdPWjLGrqH3HiCZ2GezWyEjfEIPBMhULymfzM=</Y>
</ElGamalKeyValue>
    `
)

func Test_XMLSign(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"

    // 签名
    objSign := New().
        FromString(data).
        FromXMLPrivateKey([]byte(prikeyXML)).
        Sign()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "XMLSign2-Sign")
    assertNotEmpty(signed, "XMLSign2-Sign")

    // 验证
    objVerify := New().
        FromBase64String(signed).
        FromXMLPublicKey([]byte(pubkeyXML)).
        Verify([]byte(data))

    assertError(objVerify.Error(), "XMLSign2-Verify")
    assertBool(objVerify.ToVerify(), "XMLSign2-Verify")
}

func Test_Encrypt(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "123tesfd!df"

    objEn := New().
        FromString(data).
        FromXMLPublicKey([]byte(pubkeyXML)).
        Encrypt()
    enData := objEn.ToBase64String()

    assertError(objEn.Error(), "Encrypt-Encrypt")
    assertNotEmpty(enData, "Encrypt-Encrypt")

    objDe := New().
        FromBase64String(enData).
        FromXMLPrivateKey([]byte(prikeyXML)).
        Decrypt()
    deData := objDe.ToString()

    assertError(objDe.Error(), "Encrypt-Decrypt")
    assertNotEmpty(deData, "Encrypt-Decrypt")

    assertEqual(data, deData, "Encrypt-Dedata")
}

var testBitsize = 256
var testProbability = 64

func Test_GenerateKeyPKCS1(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    obj := New().GenerateKey(testBitsize, testProbability)
    assertError(obj.Error(), "GenerateKey-Error")

    pri := obj.CreatePKCS1PrivateKey().ToKeyString()
    priPass := obj.CreatePKCS1PrivateKeyWithPassword("123").ToKeyString()
    pub := obj.CreatePKCS1PublicKey().ToKeyString()

    assertNotEmpty(pri, "GenerateKey-pri")
    assertNotEmpty(priPass, "GenerateKey-pri")
    assertNotEmpty(pub, "GenerateKey-pub")

    pri2 := obj.CreatePKCS1PrivateKey().ToKeyString()
    priPass2 := obj.CreatePKCS1PrivateKeyWithPassword("123", "DESEDE3CBC").ToKeyString()
    pub2 := obj.CreatePKCS1PublicKey().ToKeyString()

    // t.Errorf("%s, %s, %s \n", pri2, priPass2, pub2)

    assertNotEmpty(pri2, "GenerateKey-pri")
    assertNotEmpty(priPass2, "GenerateKey-pri")
    assertNotEmpty(pub2, "GenerateKey-pub")
}

func Test_GenerateKeyPKCS8(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    obj := New().GenerateKey(testBitsize, testProbability)
    assertError(obj.Error(), "GenerateKey-Error")

    pri := obj.CreatePKCS8PrivateKey().ToKeyString()
    priPass := obj.CreatePKCS8PrivateKeyWithPassword("123").ToKeyString()
    pub := obj.CreatePKCS8PublicKey().ToKeyString()

    assertNotEmpty(pri, "GenerateKey-pri")
    assertNotEmpty(priPass, "GenerateKey-pri")
    assertNotEmpty(pub, "GenerateKey-pub")

    pri2 := obj.CreatePKCS8PrivateKey().ToKeyString()
    priPass2 := obj.CreatePKCS8PrivateKeyWithPassword("123", "AES256CBC", "SHA256").ToKeyString()
    pub2 := obj.CreatePKCS8PublicKey().ToKeyString()

    // t.Errorf("%s, %s, %s \n", pri2, priPass2, pub2)

    assertNotEmpty(pri2, "GenerateKey-pri")
    assertNotEmpty(priPass2, "GenerateKey-pri")
    assertNotEmpty(pub2, "GenerateKey-pub")
}

var (
    pkcs1Prikey = `
-----BEGIN ElGamal PRIVATE KEY-----
MIGuAgEAAiEA9cZBJDM0L+NCYt4vlsMg+HdufcNdUF7Z7W2OtGogl9cCIFdwSXyl
APOj8NYVTmMwSxZMZxoXr25rL884i3vQYOd5AiB64yCSGZoX8aExbxfLYZB8O7c+
4a6oL2z2tsdaNRBL6wIgQTk/bOUCzJNfknsX+LvmpdQ9GVCd9ZiuR9t9nNi9VFsC
IFNu9DFgP10mqzkn/fB/bBrV5Xc7UPhgceZneZ5yzCDk
-----END ElGamal PRIVATE KEY-----
    `
    pkcs1EnPrikey = `
-----BEGIN ElGamal PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,b1e4e15253a2dd4f

mA/dhLT55xsoeCG8uyvRhbHRGA8JXNCTbCn8cy5IUHsJ7FSwf/9x0r09xOq3m8G1
U4RwuDU6+amtXY+yveQCoSphoA3KkW1px4WRlLnq4CGwaHj9vrc41NiSRthg8W/w
ub3s3o+E3QRX2SMysKNchTz/jdsWvryliYOUYb+HnkWywOBBcaGsSn08mSDhIwQ/
paLCOWhDigkGw55hfKARdwZKzcoiZwZNg1C7Qk82kZpTr+fww0Iqlw==
-----END ElGamal PRIVATE KEY-----
    `
    pkcs1Pubkey = `
-----BEGIN ElGamal PUBLIC KEY-----
MIGJAiEA9cZBJDM0L+NCYt4vlsMg+HdufcNdUF7Z7W2OtGogl9cCIFdwSXylAPOj
8NYVTmMwSxZMZxoXr25rL884i3vQYOd5AiB64yCSGZoX8aExbxfLYZB8O7c+4a6o
L2z2tsdaNRBL6wIgQTk/bOUCzJNfknsX+LvmpdQ9GVCd9ZiuR9t9nNi9VFs=
-----END ElGamal PUBLIC KEY-----
    `
)

var (
    pkcs8Prikey = `
-----BEGIN PRIVATE KEY-----
MHwCAQAwUwYKKwYBBAGXVQECATBFAiEA+noVToCLuNLk4FZLko7OJXNmOY6BAUNA
3hLBXv0SZKsCIFwFNqjau/88h79YkB1rL/BceW70eM8B4lCHA3woYPXPBCICIFCs
CbkGXhmcWHly2/jqgivZf3I2cTT0O4HqOmZ1IVxz
-----END PRIVATE KEY-----
    `
    pkcs8EnPrikey = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHkMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBBZny6xpUAS9PJJWXyC
p8FRAgInEDAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQwaYLhmXWTBlNy3JX
6ig8NwSBgESq+ct3cARhXWjUso5P/yITE1k4zv3YlKg90pd+ugSW6ik8yy3LvVWc
J1rO1K4MfoA2jbRO0pi74uq5c2vtl4X4zWB3YiQGhw04E4ejwQHVm0GtWDYUwzHS
wbRE9CWGY1fA6vg2JKTMizxa5KZUutn442HzQ1EWJa+anI9glNEX
-----END ENCRYPTED PRIVATE KEY-----
    `
    pkcs8Pubkey = `
-----BEGIN PUBLIC KEY-----
MHswUwYKKwYBBAGXVQECATBFAiEA+noVToCLuNLk4FZLko7OJXNmOY6BAUNA3hLB
Xv0SZKsCIFwFNqjau/88h79YkB1rL/BceW70eM8B4lCHA3woYPXPAyQAAiEAk2fe
u2+zYDS2Uob9qmSSFxfxLZkW5v8xExCig3QYhQ0=
-----END PUBLIC KEY-----
    `
)

func Test_EncryptAsn1PKCS1(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "123tesfd!df"

    objEn := New().
        FromString(data).
        FromPKCS1PublicKey([]byte(pkcs1Pubkey)).
        Encrypt()
    enData := objEn.ToBase64String()

    assertError(objEn.Error(), "Encrypt-Encrypt")
    assertNotEmpty(enData, "Encrypt-Encrypt")

    objDe := New().
        FromBase64String(enData).
        FromPKCS1PrivateKey([]byte(pkcs1Prikey)).
        Decrypt()
    deData := objDe.ToString()

    assertError(objDe.Error(), "Encrypt-Decrypt")
    assertNotEmpty(deData, "Encrypt-Decrypt")

    assertEqual(data, deData, "Encrypt-Dedata")
}

func Test_EncryptAsn1PKCS8(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "123tesfd!df"

    objEn := New().
        FromString(data).
        FromPKCS8PublicKey([]byte(pkcs8Pubkey)).
        Encrypt()
    enData := objEn.ToBase64String()

    assertError(objEn.Error(), "Encrypt-Encrypt")
    assertNotEmpty(enData, "Encrypt-Encrypt")

    objDe := New().
        FromBase64String(enData).
        FromPKCS8PrivateKey([]byte(pkcs8Prikey)).
        Decrypt()
    deData := objDe.ToString()

    assertError(objDe.Error(), "Encrypt-Decrypt")
    assertNotEmpty(deData, "Encrypt-Decrypt")

    assertEqual(data, deData, "Encrypt-Dedata")
}

func Test_CheckKeyPair(t *testing.T) {
    assertBool := cryptobin_test.AssertBoolT(t)

    objCheck1 := New().
        FromPKCS1PrivateKey([]byte(pkcs1Prikey)).
        FromPKCS1PublicKey([]byte(pkcs1Pubkey)).
        CheckKeyPair()
    assertBool(objCheck1, "CheckKeyPair1")

    objCheck12 := New().
        FromPKCS1PrivateKeyWithPassword([]byte(pkcs1EnPrikey), "123").
        FromPKCS1PublicKey([]byte(pkcs1Pubkey)).
        CheckKeyPair()
    assertBool(objCheck12, "CheckKeyPair12")

    objCheck2 := New().
        FromPKCS8PrivateKey([]byte(pkcs8Prikey)).
        FromPKCS8PublicKey([]byte(pkcs8Pubkey)).
        CheckKeyPair()
    assertBool(objCheck2, "CheckKeyPair2")

    objCheck22 := New().
        FromPKCS8PrivateKeyWithPassword([]byte(pkcs8EnPrikey), "123").
        FromPKCS8PublicKey([]byte(pkcs8Pubkey)).
        CheckKeyPair()
    assertBool(objCheck22, "CheckKeyPair22")
}

func Test_EncryptAsn1_1(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "123tesfd!df"

    objEn := New().
        FromString(data).
        FromPublicKey([]byte(pkcs1Pubkey)).
        Encrypt()
    enData := objEn.ToBase64String()

    assertError(objEn.Error(), "Encrypt-Encrypt")
    assertNotEmpty(enData, "Encrypt-Encrypt")

    objDe := New().
        FromBase64String(enData).
        FromPrivateKey([]byte(pkcs1Prikey)).
        Decrypt()
    deData := objDe.ToString()

    assertError(objDe.Error(), "Encrypt-Decrypt")
    assertNotEmpty(deData, "Encrypt-Decrypt")

    assertEqual(data, deData, "Encrypt-Dedata")

    objDe2 := New().
        FromBase64String(enData).
        FromPrivateKeyWithPassword([]byte(pkcs1EnPrikey), "123").
        Decrypt()
    deData2 := objDe2.ToString()

    assertError(objDe2.Error(), "Encrypt-Decrypt")
    assertNotEmpty(deData2, "Encrypt-Decrypt")

    assertEqual(data, deData2, "Encrypt-Dedata")
}

func Test_EncryptAsn1_2(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "123tesfd!df"

    objEn := New().
        FromString(data).
        FromPublicKey([]byte(pkcs8Pubkey)).
        Encrypt()
    enData := objEn.ToBase64String()

    assertError(objEn.Error(), "Encrypt-Encrypt")
    assertNotEmpty(enData, "Encrypt-Encrypt")

    objDe := New().
        FromBase64String(enData).
        FromPrivateKey([]byte(pkcs8Prikey)).
        Decrypt()
    deData := objDe.ToString()

    assertError(objDe.Error(), "Encrypt-Decrypt")
    assertNotEmpty(deData, "Encrypt-Decrypt")

    assertEqual(data, deData, "Encrypt-Dedata")

    objDe2 := New().
        FromBase64String(enData).
        FromPrivateKeyWithPassword([]byte(pkcs8EnPrikey), "123").
        Decrypt()
    deData2 := objDe2.ToString()

    assertError(objDe2.Error(), "Encrypt-Decrypt")
    assertNotEmpty(deData2, "Encrypt-Decrypt")

    assertEqual(data, deData2, "Encrypt-Dedata")
}

func Test_EncryptAsn1_3(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "123tesfd!df"

    t.Run("EncryptAsn1_3 EncryptBytes", func(t *testing.T) {
        objEn := New().
            FromString(data).
            FromPublicKey([]byte(pkcs8Pubkey)).
            EncryptBytes()
        enData := objEn.ToBase64String()

        assertError(objEn.Error(), "Encrypt-Encrypt")
        assertNotEmpty(enData, "Encrypt-Encrypt")

        objDe := New().
            FromBase64String(enData).
            FromPrivateKey([]byte(pkcs8Prikey)).
            DecryptBytes()
        deData := objDe.ToString()

        assertError(objDe.Error(), "Encrypt-Decrypt")
        assertNotEmpty(deData, "Encrypt-Decrypt")

        assertEqual(data, deData, "Encrypt-Dedata")
    })

    t.Run("EncryptAsn1_3 EncryptASN1", func(t *testing.T) {
        objEn := New().
            FromString(data).
            FromPublicKey([]byte(pkcs8Pubkey)).
            EncryptASN1()
        enData := objEn.ToBase64String()

        assertError(objEn.Error(), "Encrypt-Encrypt")
        assertNotEmpty(enData, "Encrypt-Encrypt")

        objDe := New().
            FromBase64String(enData).
            FromPrivateKey([]byte(pkcs8Prikey)).
            DecryptASN1()
        deData := objDe.ToString()

        assertError(objDe.Error(), "Encrypt-Decrypt")
        assertNotEmpty(deData, "Encrypt-Decrypt")

        assertEqual(data, deData, "Encrypt-Dedata")
    })

    t.Run("EncryptAsn1_3 Encrypt With ASN1", func(t *testing.T) {
        objEn := New().
            FromString(data).
            FromPublicKey([]byte(pkcs8Pubkey)).
            WithEncodingASN1().
            Encrypt()
        enData := objEn.ToBase64String()

        assertError(objEn.Error(), "Encrypt-Encrypt")
        assertNotEmpty(enData, "Encrypt-Encrypt")

        objDe := New().
            FromBase64String(enData).
            FromPrivateKey([]byte(pkcs8Prikey)).
            WithEncodingASN1().
            Decrypt()
        deData := objDe.ToString()

        assertError(objDe.Error(), "Encrypt-Decrypt")
        assertNotEmpty(deData, "Encrypt-Decrypt")

        assertEqual(data, deData, "Encrypt-Dedata")
    })

    t.Run("EncryptAsn1_3 Encrypt With Bytes", func(t *testing.T) {
        objEn := New().
            FromString(data).
            FromPublicKey([]byte(pkcs8Pubkey)).
            WithEncodingBytes().
            Encrypt()
        enData := objEn.ToBase64String()

        assertError(objEn.Error(), "Encrypt-Encrypt")
        assertNotEmpty(enData, "Encrypt-Encrypt")

        objDe := New().
            FromBase64String(enData).
            FromPrivateKey([]byte(pkcs8Prikey)).
            WithEncodingBytes().
            Decrypt()
        deData := objDe.ToString()

        assertError(objDe.Error(), "Encrypt-Decrypt")
        assertNotEmpty(deData, "Encrypt-Decrypt")

        assertEqual(data, deData, "Encrypt-Dedata")
    })

}

func Test_Sign_2(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"

    t.Run("Test_Sign_2 1", func(t *testing.T) {
        // 签名
        objSign := New().
            FromString(data).
            FromPrivateKey([]byte(pkcs8Prikey)).
            Sign()
        signed := objSign.ToBase64String()

        assertError(objSign.Error(), "Test_Sign_2-Sign")
        assertNotEmpty(signed, "Test_Sign_2-Sign")

        // 验证
        objVerify := New().
            FromBase64String(signed).
            FromPublicKey([]byte(pkcs8Pubkey)).
            Verify([]byte(data))

        assertError(objVerify.Error(), "Test_Sign_2-Verify")
        assertBool(objVerify.ToVerify(), "Test_Sign_2-Verify")
    })

    t.Run("Test_Sign_2 2", func(t *testing.T) {
        // 签名
        objSign := New().
            FromString(data).
            FromPrivateKey([]byte(pkcs8Prikey)).
            WithEncodingASN1().
            Sign()
        signed := objSign.ToBase64String()

        assertError(objSign.Error(), "Test_Sign_2-Sign")
        assertNotEmpty(signed, "Test_Sign_2-Sign")

        // 验证
        objVerify := New().
            FromBase64String(signed).
            FromPublicKey([]byte(pkcs8Pubkey)).
            WithEncodingASN1().
            Verify([]byte(data))

        assertError(objVerify.Error(), "Test_Sign_2-Verify")
        assertBool(objVerify.ToVerify(), "Test_Sign_2-Verify")
    })

    t.Run("Test_Sign_2 3", func(t *testing.T) {
        // 签名
        objSign := New().
            FromString(data).
            FromPrivateKey([]byte(pkcs8Prikey)).
            WithEncodingBytes().
            Sign()
        signed := objSign.ToBase64String()

        assertError(objSign.Error(), "Test_Sign_2-Sign")
        assertNotEmpty(signed, "Test_Sign_2-Sign")

        // 验证
        objVerify := New().
            FromBase64String(signed).
            FromPublicKey([]byte(pkcs8Pubkey)).
            WithEncodingBytes().
            Verify([]byte(data))

        assertError(objVerify.Error(), "Test_Sign_2-Verify")
        assertBool(objVerify.ToVerify(), "Test_Sign_2-Verify")
    })

    t.Run("Test_Sign_2 4", func(t *testing.T) {
        // 签名
        objSign := New().
            FromString(data).
            FromPrivateKey([]byte(pkcs8Prikey)).
            SignASN1()
        signed := objSign.ToBase64String()

        assertError(objSign.Error(), "Test_Sign_2-Sign")
        assertNotEmpty(signed, "Test_Sign_2-Sign")

        // 验证
        objVerify := New().
            FromBase64String(signed).
            FromPublicKey([]byte(pkcs8Pubkey)).
            VerifyASN1([]byte(data))

        assertError(objVerify.Error(), "Test_Sign_2-Verify")
        assertBool(objVerify.ToVerify(), "Test_Sign_2-Verify")
    })

    t.Run("Test_Sign_2 5", func(t *testing.T) {
        // 签名
        objSign := New().
            FromString(data).
            FromPrivateKey([]byte(pkcs8Prikey)).
            SignBytes()
        signed := objSign.ToBase64String()

        assertError(objSign.Error(), "Test_Sign_2-Sign")
        assertNotEmpty(signed, "Test_Sign_2-Sign")

        // 验证
        objVerify := New().
            FromBase64String(signed).
            FromPublicKey([]byte(pkcs8Pubkey)).
            VerifyBytes([]byte(data))

        assertError(objVerify.Error(), "Test_Sign_2-Verify")
        assertBool(objVerify.ToVerify(), "Test_Sign_2-Verify")
    })

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

        gen := New().GenerateKey(256, 64)

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
