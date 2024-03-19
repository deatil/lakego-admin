package rsa

import (
    "bytes"
    "errors"
    "testing"
    "crypto/rand"
    mrand "math/rand"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

// Test_PrimeKeyGeneration
func Test_PrimeKeyGeneration(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    size := 768
    if testing.Short() {
        size = 256
    }

    obj := NewRSA().GenerateMultiPrimeKey(3, size)

    objPriKey := obj.CreatePKCS1PrivateKey()

    assertError(objPriKey.Error(), "objPriKey")
    assertNotEmpty(objPriKey.ToKeyString(), "objPriKey")

    objPubKey := obj.CreatePKCS1PublicKey()

    assertError(objPubKey.Error(), "objPubKey")
    assertNotEmpty(objPubKey.ToKeyString(), "objPubKey")
}

var (
    testSignPrikeyPkcs1En = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,c47d6aef98e01776d8519936adb449ad

2YSwbFUmWFWYlMLtkCWI2B8k8WxcmSyuu4vhLcHZrsIYm0EIe3xX7AkfXodZgO1g
vjjbX4w/qaB3WPg4Re9TxgaLqEEY0DRkuP4m/kDsu40ZQyMlGrXKl3Yp8D6Te2Wf
RcRBgibWwNJVgZYQ6nY/82SA2gIcvCQVo0VZVQQqnlULyhpMt2yR2N3HprD95BI3
yhoOae81qLikjVdWpoTwjSu8uHLw2qwWSrOjBgUSHjbXJBsvwIEorAGkvtTYWKCn
tUG0Rn40gDqvrEvowYdIxriZdvndcYbijsqsP3pOTPBP2rYiFT3Bj19FLC11R8bv
eXYs7/YgsVH+l7XhJabJPJSH4Zuz/TDkcVdrzBxtLxFsFVOqs68QfJ/xuM6SLYxy
6YG2Oq8MAdG96QHYUGxnIZBNXfBGsYbVGc4fSRv8FiCgXOX2l1F9dTlbX2FluKgb
om+SrCKZkWn/jEjSdnnCvkC22JzqyY2KAcLkSVUx+ZtQCl+0YHZHrk4Vkz9GvS6f
WOtBtj1YQ8BAhMpGy+eRxTIHBHHYBYosqBQ3B/5dexoFleznCHUGHzGGXRCd+ty9
9QJrur/3QZg4T/68JDypp3nIY4CcUdNOhoL1BjT0gvzaosZhAohcZaO7mCDCUQXG
oBvbC6wbNFNzm0iLBUIdNPoRujiSKgxk+m748IzJBpAgC9s3PjmNmnJQrywu9A/s
YkVBTYwccqhVzjSYBEnGSnBWcfvTSeSf2CoaSMnju9aNSt9gIuNTe5nact4VT0+T
VCx2NqZAU5so2yhpG8g2H393/3QF81nkeuFqkSDgDvPYenrhEOs1Lbn4mRRDBAJY
-----END RSA PRIVATE KEY-----
    `

    testSignPrikeyPkcs8En = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIC5TBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQj5kaaZMiw2Ha3s4z
F4e0LgICJxAwDAYIKoZIhvcNAgcFADAdBglghkgBZQMEARYEEN49eNpe9aDZN0/J
U05yLWoEggKAiBUPV+9o9iMxLdFTLzvSTSJAUvXxEnbY+SfeCW25qBvCsydO7Iuy
HfL+3YYKvxH4j115RG5uWA3BK8EpfrWGlAXAacTfPZim7AUbe6Omf+rYi3KWXTQ0
5StQHiMS5t0AhWGWk1vUwL33mJK6ceKR7BhfGliI4QGyWeTeGqJkq0P7m9Fo9ylY
MP2POg/0RutacEoB2BUvHxPu+RJZoj/3K2nvLtPJo5wWLBQW4F3TdPSn79VlGaWN
gTDY21sYPVz+5kIl3RSnPWwpOCUw23ZNGaHVX4xtnVzzBkC1cJeGeaBgZjht5uf1
wuh57g/neLBzjBUHKxAs3OdDUKYejg/HFrId0f+nDCuRwoJeyEwxkt7fJizIFftH
9Ks42I5ndTcB7zs1Eb5IF/HYYWHTzNLRm+Wt57LyoG++nOv0kMmlHiX9omgtsveA
Y6ONUeTxWwa2ljP5zpslGXYhmVyRg6hC/LnoqfUFf2jV5m+epvOOSQgQkzIrxN9j
QTquQhzUaaKpTBPPvkIHSb6568PLvhHqx/ilDGvp9UAWtO6bfXGwOIZcL3p9WetE
2sasOjp/VhgUJD37a0G7pwZpAoLsNC+tEUtaFkw5nNLMFM0urGYHBsVNZt/N2ibM
gKkq5AB/Zv4foXuqxsZM3k6V1uDpesQXt+/Xnqysi9MQkk16r+N9+uctugReej8M
nPaPvK54bnJ7HA9fnKt1Vf+x/NLGLdIX4xIzqBC4xOqLQlTbStRw2XRDGespR376
JnsP82g2PQN+dH0QNbW/C/eq5mfpAxh6x8JFBaha7/33czh465yg7Qpos+AMGK/D
TYEOgSzqZlhf5ISMB5uAwOW6k4TuJAUbrA==
-----END ENCRYPTED PRIVATE KEY-----
    `

    testSignPubkey = `
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDbvgUxbNl35YrbZDPCVYOdJSxX
j69JLx3LwRUfGj34BdMb/DJuuoDzVA+fppISMul9mNaspHxguWsHgnvSpc4Swceq
t5Rr4E4VBnudvTe7BU9aHmbY4g7aldJ+S5gC3dT11wHz6Sre+2a74xsZxs51+M0Q
tGjMoEruLNj7fkPcNQIDAQAB
-----END PUBLIC KEY-----
    `
)

func Test_RSAPkcs1Sign(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertTrue := cryptobin_test.AssertTrueT(t)

    data := "test-pass"

    obj := NewRSA()

    sign := obj.
        FromString(data).
        FromPKCS1PrivateKeyWithPassword([]byte(testSignPrikeyPkcs1En), "123").
        SetSignHash("SHA256").
        Sign()
    signData := sign.ToBase64String()

    assertError(sign.Error(), "RSAPkcs1Sign-sign")
    assertNotEmpty(signData, "RSAPkcs1Sign-sign")

    verify := obj.
        FromBase64String(signData).
        FromPublicKey([]byte(testSignPubkey)).
        SetSignHash("SHA256").
        Verify([]byte(data))
    verifyData := verify.ToVerify()

    assertError(verify.Error(), "RSAPkcs1Sign-verify")
    assertTrue(verifyData, "RSAPkcs1Sign-verify")
}

func Test_RSAPkcs8Sign(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertTrue := cryptobin_test.AssertTrueT(t)

    data := "test-pass22222"

    obj := NewRSA()

    sign := obj.
        FromString(data).
        FromPKCS8PrivateKeyWithPassword([]byte(testSignPrikeyPkcs8En), "123").
        SetSignHash("SHA256").
        Sign()
    signData := sign.ToBase64String()

    assertError(sign.Error(), "RSAPkcs1Sign-sign")
    assertNotEmpty(signData, "RSAPkcs1Sign-sign")

    verify := obj.
        FromBase64String(signData).
        FromPublicKey([]byte(testSignPubkey)).
        SetSignHash("SHA256").
        Verify([]byte(data))
    verifyData := verify.ToVerify()

    assertError(verify.Error(), "RSAPkcs1Sign-verify")
    assertTrue(verifyData, "RSAPkcs1Sign-verify")
}

var (
    testPubN = "CCE3A1FA0E3EADEE4FE464F7D45F5009DBF2D77FF9DD9D822F41E8AD6F47762FE46569E2EE39906CE557328CF9CFE33906D4D0494CADEE2357B90178D3200DFF96EBB21053DC65AEFA458BC62C5540E3343F2968F934EAD87DAFCA6681C78CD3936E14808A74D5C7CD1EE10C7C3400C52358DF30B9383C70FF4E853ADD5D21D5"
    testPubE = "10001"
    testPubEnd = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDM46H6Dj6t7k/kZPfUX1AJ2/LX
f/ndnYIvQeitb0d2L+RlaeLuOZBs5VcyjPnP4zkG1NBJTK3uI1e5AXjTIA3/luuy
EFPcZa76RYvGLFVA4zQ/KWj5NOrYfa/KZoHHjNOTbhSAinTVx80e4Qx8NADFI1jf
MLk4PHD/ToU63V0h1QIDAQAB
-----END PUBLIC KEY-----
`
)

func Test_PubNE(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)

    en := NewRSA().
        FromPublicKeyNE(testPubN, testPubE).
        CreatePKCS8PublicKey()
    enData := en.ToKeyString()

    assertError(en.Error(), "PubNE-make")
    assertNotEmpty(enData, "PubNE-make")

    assertEqual(enData, testPubEnd, "PubNE-make")
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

        gen := New().GenerateKey(2048)

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

func Test_ManyTests(t *testing.T) {
    obj := NewRSA().GenerateKey(1024)
    priKey := obj.CreatePKCS8PrivateKey().ToKeyBytes()
    pubKey := obj.CreatePKCS8PublicKey().ToKeyBytes()

    rsaObj := NewRSA().
        FromPKCS8PublicKey(pubKey).
        FromPKCS8PrivateKey(priKey)

    for i := 0; i < 50; i++ {
        odata := make([]byte, mrand.Intn(100) + 50)
        rand.Read(odata)

        if len(odata)/8 != 0 {
            // t.Errorf("fail len %d", len(odata)/8)
            continue
        }

        cypt := rsaObj.FromBytes(odata).Encrypt().
            OnError(func(errs []error) {
                if len(errs) > 0 {
                    e := errors.Join(errs...).Error()
                    t.Errorf("Encrypt err: %s", e)
                }
            }).
            ToBytes()
        data := rsaObj.FromBytes(cypt).Decrypt().
            OnError(func(errs []error) {
                if len(errs) > 0 {
                    e := errors.Join(errs...).Error()
                    t.Errorf("Decrypt err: %s", e)
                }
            }).
            ToBytes()

        if !bytes.Equal(odata, data) {
            mod := len(odata)%8
            t.Errorf("fail, got %x(len=%d), want %x(len=%d,mod=%d)", data, len(data), odata, len(odata), mod)
        }
    }
}

var testWeappRSAPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA3FoQOmOl5/CF5hF7ta4EzCy2LaU3Eu2k9DBwQ73J82I53Sx9
LAgM1DH3IsYohRRx/BESfbdDI2powvr6QYKVIC+4Yavwg7gzhZRxWWmT1HruEADC
ZAgkUCu+9Il/9FPuitPSoIpBd07NqdkkRe82NBOfrKTdhge/5zd457fl7J81Q5VT
IxO8vvq7FSw7k6Jtv+eOjR6SZOWbbUO7f9r4UuUkXmvdGv21qiqtaO1EMw4tUCEL
zY73M7NpCH3RorlommYX3P6q0VrkDHrCE0/QMhmHsF+46E+IRcJ3wtEj3p/mO1Vo
CpEhawC1U728ZUTwWNEii8hPEhcNAZTKaQMaTQIDAQABAoIBAQCXv5p/a5KcyYKc
75tfgekh5wTLKIVmDqzT0evuauyCJTouO+4z/ZNAKuzEUO0kwPDCo8s1MpkU8boV
1Ru1M8WZNePnt65aN+ebbaAl8FRzNvltoeg9VXIUmBvYcjzhOVAE4V2jW7M8A9QU
zUpyswuED6OeFKfOHtYk2In2IipAqhfbyc6gn7uZSWTQsoO6hGBRQ7Ejx+vgwrbx
ZKVZ7UXbPHD0lOEPraA3PH/QUeUKpNwK2NXQoBxWcR283/HxFSAjjSSsGSBKsCnw
DN55P2FQ0HNi5YrwUNT9190NIXSeygaRy1b+D+yBfm+yE7/qXwHLZCHsjO+2tMSS
3KGjllTBAoGBAP9FPeYNKZuu5jt9RpZwXCc9E7Iz7bmM7zws6dun6dQH0xVVWFVm
iGIu07eqyB8HNagXseFzoXLV5EQx+3DaB0bAH+ZEpHGJJpAWSLusigssFUFuTvTF
w+rC5hxOfidMa6+93SU5pWeJb0zJF8PRDaJ3UmwlwpYubF17sT4PD6p9AoGBANz7
RlhRSFvggJjhEMpek3OIYWrrlRNO2MVcP7i/fGNTHhrw7OHcNGRof54QZ2Y0baL7
1vHNokbK2mnT+cQXY/gXMmcE/eV4xyRGYiIL9nBdrkLerc43EYPv+evDvgyji6+y
4np5cKqHrS8F+YzATk82Jt9HgdI2MvfbJTkSbmgRAoGAHNPL9rPb1An/VA6Ery6H
KaM7Gy/EE+U3ixsjWbvvqxMrIkieDh7jHftdy2sM6Hwe8hmi6+vr+pTvD0h5tbfZ
hILj11Q/Idc0NKdflVoZyMM0r0vuvLOsuVFDPUUb+AIoUxNk6vREmpmpqQk4ltN/
763779yfyef6MuBqFrEKut0CgYB9FfsuuOv1nfINF7EybDCZAETsiee7ozEPHnWv
dSzK6FytMV1VSBmcEI7UgUKWVu0MifOUsiq+WcsihmvmNLtQzoioSeoSP7ix7ulT
jmP0HQMsNPI7PW67uVZFv2pPqy/Bx8dtPlqpHN3KNV6Z7q0lJ2j/kHGK9UUKidDb
KnS2kQKBgHZ0cYzwh9YnmfXx9mimF57aQQ8aFc9yaeD5/3G2+a/FZcHtYzUdHQ7P
PS35blD17/NnhunHhuqakbgarH/LIFMHITCVuGQT4xS34kFVjFVhiT3cHfWyBbJ6
GbQuzzFxz/UKDDKf3/ON41k8UP20Gdvmv/+c6qQjKPayME81elus
-----END RSA PRIVATE KEY-----
`
var testWeappRSAPublicKey = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzkP2qWQKaTWSvcWkXR72
lzeQay/PlEDT9hGfL3E8ojJXZRUwNm9FD6YMeyJBAUTp62DjnsoVhLFMMq0i1t2X
qElBUZ4C+DSao9gT1KQdEZN8v8CddFsoEbYYLY5xo9ICmuws56uyNrLaZ772kXxU
fJtXxqjHvwA2xTvkb847dXWIQTSzk+aCWqTwMSLD2AH90YnOw19fDO/InKJQ/1m6
Nh7HKOxL79kZ1I5SSov+2H7XrIePxqVx3KBrpgZ9YQPJaS3+L8HbxzDHifPCTzGC
u6uJ89ou4yTT73AlAsJ8Cf9/vPIesLw9wPVe+9G31UE0wEBJezfvXQ4PLJV/aWQy
CQIDAQAB
-----END PUBLIC KEY-----
`

// https://developers.weixin.qq.com/miniprogram/dev/OpenApiDoc/getting_started/api_signature.html
// 微信小程序 api RSAwithSHA256 验证测试
func Test_Weapp_RSA_Verify(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertTrue := cryptobin_test.AssertTrueT(t)

    req_data := `{"iv":"r2WDQt56rEAmMuoR","data":"HExs66Ik3el+iM4IpeQ7SMEN934FRLFYOd3EmeaIrpP4EPTHckoco6O+PaoRZRa3lqaPRZT7r52f7LUok6gLxc6cdR8C4vpIIfh4xfLC4L7FNy9GbuMK1hcoi8b7gkWJcwZMkuCFNEDmqn3T49oWzAQOrY4LZnnnykv6oUJotdAsnKvmoJkLK7hRh7M2B1d2UnTnRuoIyarXc5Iojwoghx4BOvnV","authtag":"z2BFD8QctKXTuBlhICGOjQ=="}`
    data := "https://api.weixin.qq.com/wxa/getuserriskrank\nwxba6223c06417af7b\n1635927956\n" + req_data
    signData := "Ht0VfQkkEweJ4hU266C14Aj64H9AXfkwNi5zxUZETCvR2svU1ZYdosDhFX/voLj1TyszqKsVxAlENGt7PPZZ8RQX7jnA4SKhiPUhW4LTbyTenisHJ+ohSfDjYnXavjQsBHspFS+BlPHuSSJ2xyQzw1+HuC6nid09ZL4FnGSYo4OI5MJrSb9xLzIVZMIDuUQchGKi/KaB1KzxECLEZcfjqbAgmxC7qOmuBLyO1WkHYDM95NJrHJWba5xv4wrwPru9yYTJSNRnlM+zrW5w9pOubC4Jtj3szTAEuOz9AcqUmgaAvMLNAIa8hfODLRe3n/cu4SgYlN/ZkNRU4QXVNbPGMg=="

    obj := NewRSA()

    verify := obj.
        FromBase64String(signData).
        FromPublicKey([]byte(testWeappRSAPublicKey)).
        SetSignHash("SHA256").
        VerifyPSS([]byte(data))
    verifyData := verify.ToVerify()

    assertError(verify.Error(), "Test_Weapp_RSA_Verify-verify")
    assertTrue(verifyData, "Test_Weapp_RSA_Verify-verify")
}
