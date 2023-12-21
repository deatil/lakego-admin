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
MIGMAgEAAiBG2QPQa28N1axYmAXQYhivlso0yY5wVjJaO1TZBkDAyQIhAMJmSRKC
LPAqJj1PUsYgB7djyNDhq5iadDbk1Hn/wcfvAiA9c0jJy+hHyNMHhVsbV0Dzq3s7
+dYJtrWfQau+UARvFQIgTafZkEv/oojOjX1IjyYXtG14Fm6dTM31hxGfncpRiys=
-----END EIGamal PRIVATE KEY-----
    `
    pkcs1EnPrikey = `
-----BEGIN EIGamal PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,04cc49efb5b3887a

sTsQmSlTGC+SFzNng5Ct2kxTSBj0rcOj/2JO2rWkrOLou3q996Rx1LcifvZoQcqW
Vjmh1KTCPFS3SoMA88f6s0o7EFFiVJz7QYyVPx9bFUSyh939NSlHLRKPCeMteKVd
ohjhqjlJRNcZ1ohD5e7dYAINenfDRzaf4481HEVof74XAg/guweocvuTFUyINMfK
-----END EIGamal PRIVATE KEY-----
    `
    pkcs1Pubkey = `
-----BEGIN EIGamal PUBLIC KEY-----
MGcCIEbZA9Brbw3VrFiYBdBiGK+WyjTJjnBWMlo7VNkGQMDJAiEAwmZJEoIs8Com
PU9SxiAHt2PI0OGrmJp0NuTUef/Bx+8CID1zSMnL6EfI0weFWxtXQPOrezv51gm2
tZ9Bq75QBG8V
-----END EIGamal PUBLIC KEY-----
    `
)

var (
    pkcs8Prikey = `
-----BEGIN PRIVATE KEY-----
MHkCAQAwUAYGKw4HAgEBMEYCIQCy4rpY7/Z7AEFkeynhVsYJOKNq0D9NtUWf+puN
qK7zrwIhAOjg+O+HXtVdj3vN72H5a6kL+57ITnNRNB6FcqB+Zz5jBCICIFPOG8D1
HeUCUbxK7U5ZrjnfS0dvDcRA5ho6b5cpad8q
-----END PRIVATE KEY-----
    `
    pkcs8EnPrikey = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHkMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBAHndBcwCbGl/H+ABqb
GA1NAgInEDAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQrAC6gJNgTPM6+tpe
rexsJgSBgDkbDfoCerEfFxM0spyJiwXuCDEBDwo84GD8wNYviypWsujku7kiaIhY
ht7LuPsGQ7nlQqO8cZBpnajR/YS1gJYwAY8DVFqxm4yjwuAu7glptnvtylRR6lCV
esEaQVmbvxLO/VyIT6h5FwCEMahGs5Sz8BkoIU+DtRinq53+BzNx
-----END ENCRYPTED PRIVATE KEY-----
    `
    pkcs8Pubkey = `
-----BEGIN PUBLIC KEY-----
MHgwUAYGKw4HAgEBMEYCIQCy4rpY7/Z7AEFkeynhVsYJOKNq0D9NtUWf+puNqK7z
rwIhAOjg+O+HXtVdj3vN72H5a6kL+57ITnNRNB6FcqB+Zz5jAyQAAiEA0jS+mkks
HAqGE16YbE8QDW1pod+8A/FO09oEMqvPnA0=
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
