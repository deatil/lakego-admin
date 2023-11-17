package elgamal

import (
    "testing"
    "crypto/rand"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var (
    prikeyXML = `
<EIGamalKeyValue>
    <G>vG406oGr5OqG0mMOtq5wWo/aGWWE8EPiPl09/I+ySxs=</G>
    <P>9W35RbKvFgfHndG9wVvFDMDw86BClpDk6kdeGr1ygLc=</P>
    <Y>120jHKCdPWjLGrqH3HiCZ2GezWyEjfEIPBMhULymfzM=</Y>
    <X>BjtroR34tS5cvF5YNJaxmOjGDas43wKFunHCYS4P6CQ=</X>
</EIGamalKeyValue>
    `
    pubkeyXML = `
<EIGamalKeyValue>
    <G>vG406oGr5OqG0mMOtq5wWo/aGWWE8EPiPl09/I+ySxs=</G>
    <P>9W35RbKvFgfHndG9wVvFDMDw86BClpDk6kdeGr1ygLc=</P>
    <Y>120jHKCdPWjLGrqH3HiCZ2GezWyEjfEIPBMhULymfzM=</Y>
</EIGamalKeyValue>
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

    assertNotEmpty(pri2, "GenerateKey-pri")
    assertNotEmpty(priPass2, "GenerateKey-pri")
    assertNotEmpty(pub2, "GenerateKey-pub")
}

var (
    pkcs1Prikey = `
-----BEGIN EIGamal PRIVATE KEY-----
MIGOAgEAAiEAm3984TD8mLcbfO9yBS0JgETilmmzRU6G3a/Z7oGx2CsCIQDLNyir
IBznc0d8nECuJZ8x0x5ToZJ6cqqXobFnhewuIwIhAMXX2PFykwiY9uOBa3/9YpKj
WeePhxAvyHMFdJUTGhUDAiAJKb80n3yq8os1rof3ZrivBxJxMIKgDvBUHA2eSTXu
ZQ==
-----END EIGamal PRIVATE KEY-----
    `
    pkcs1EnPrikey = `
-----BEGIN EIGamal PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,cd748069ab721cdaf858332cf48fb445

zhkRM8PrHupD8IKRItv2AbDwzkgwqd8HFmFJvUcYKrDjFfkxl0JSEDh3LQYCIOf5
iofXjTUjxJjzJNtua+8mKIJxKAMxP+zLz8Crirnmm06WL6orYDvAmi23LL0+nbuf
MmKXg7u8ErCOu8fye+5aG/iGNT+cO84PIUBCq6ruC9nBh9Xd+eFPrHyE2902eRRy
t7qNAufyCbFmZJP/WwZlOA==
-----END EIGamal PRIVATE KEY-----
    `
    pkcs1Pubkey = `
-----BEGIN EIGamal PUBLIC KEY-----
MGkCIQCbf3zhMPyYtxt873IFLQmAROKWabNFTobdr9nugbHYKwIhAMs3KKsgHOdz
R3ycQK4lnzHTHlOhknpyqpehsWeF7C4jAiEAxdfY8XKTCJj244Frf/1ikqNZ54+H
EC/IcwV0lRMaFQM=
-----END EIGamal PUBLIC KEY-----
    `
)

var (
    pkcs8Prikey = `
-----BEGIN PRIVATE KEY-----
MHsCAQAwCgYGKw4HAgEBBQAEajBoAiEAh26+uiviD9m/QEQE6KJO/BGL62/EDp5Q
4ruIcuWMrOwCIQDByRshe0Br4UkoJPLD0zoP3nYC9eR2u/CxtEJuDyp+TwIgGT4z
e6hUUi8Jx/r2uH0l/AaUN15pJpBcX2Xm0s8GLzo=
-----END PRIVATE KEY-----
    `
    pkcs8EnPrikey = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHWMFEGCSqGSIb3DQEFDTBEMCMGCSqGSIb3DQEFDDAWBBAm0cRa05+WN3aka1a5
75p4AgInEDAdBglghkgBZQMEASoEEIhMsYKJQMAnawshtW8UdKAEgYCkfWdI/ZEC
BBe+mwSIvlIX7rkiQDoLhbSJaCuDpuhlCHKe/ALzK6lSpPr+5wnF0wttQdrsDdr5
e6qb7UfGYLsKDfVqgOinMxvRRKsRVBZ28aWYD38u8ly2ZACg/4GjQ9x9dHsdOR/a
BmEHN8CnynXHRZXb+dOnCs22PoNuVEVwsQ==
-----END ENCRYPTED PRIVATE KEY-----
    `
    pkcs8Pubkey = `
-----BEGIN PUBLIC KEY-----
MHkwCgYGKw4HAgEBBQADawAwaAIhAIduvror4g/Zv0BEBOiiTvwRi+tvxA6eUOK7
iHLljKzsAiEAwckbIXtAa+FJKCTyw9M6D952AvXkdrvwsbRCbg8qfk8CIB68rz21
IQLlX/fsm/jmML/VbtGOKAGGHfAaosw7FAOw
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
