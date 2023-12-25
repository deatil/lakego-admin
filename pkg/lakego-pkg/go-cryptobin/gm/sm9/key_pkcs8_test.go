package sm9

import (
    "testing"
    "crypto/rand"
    "encoding/pem"
    "encoding/hex"
    // "encoding/base64"

    "golang.org/x/crypto/cryptobyte"
    cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

// t.Error(string(encodePEM(mpubkeyDer, "m PUBLIC KEY")))
func Test_SignPrivateKey(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    mprikey, err := GenerateSignMasterPrivateKey(rand.Reader)
    if err != nil {
        t.Errorf("mprikey gen failed:%s", err)
        return
    }

    var hid byte = 1
    var uid = []byte("Alice")

    prikey, err := GenerateSignPrivateKey(mprikey, uid, hid)
    if err != nil {
        t.Errorf("prikey gen failed:%s", err)
        return
    }

    // ==========

    mprikeyDer, err := MarshalPrivateKey(mprikey)
    if err != nil {
        t.Fatal(err)
    }

    if len(mprikeyDer) == 0 {
        t.Error("mprikey der make error")
    }

    mprikey2, err := ParsePrivateKey(mprikeyDer)
    if err != nil {
        t.Fatal(err)
    }

    /*
    if !mprikey2.(*SignMasterPrivateKey).Equal(mprikey) {
        t.Error("m prikey make error")
    }
    */

    assertEqual(mprikey2.(*SignMasterPrivateKey).D, mprikey.D, "mprikey")
    // assertEqual(mprikey2.(*SignMasterPrivateKey).SignMasterPublicKey, mprikey.SignMasterPublicKey, "mprikey")

    // ==========

    prikeyDer, err := MarshalPrivateKey(prikey)
    if err != nil {
        t.Fatal(err)
    }

    if len(mprikeyDer) == 0 {
        t.Error("prikey der make error")
    }

    prikey2, err := ParsePrivateKey(prikeyDer)
    if err != nil {
        t.Fatal(err)
    }

    assertEqual(prikey2, prikey, "prikey")
}

func Test_SignPublicKey(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    mprikey, err := GenerateSignMasterPrivateKey(rand.Reader)
    if err != nil {
        t.Errorf("mprikey gen failed:%s", err)
        return
    }

    mpubkey := mprikey.PublicKey()

    mpubkeyDer, err := MarshalPublicKey(mpubkey)
    if err != nil {
        t.Fatal(err)
    }

    if len(mpubkeyDer) == 0 {
        t.Error("pub pem make error")
    }

    mpubkey2, err := ParsePublicKey(mpubkeyDer)
    if err != nil {
        t.Fatal(err)
    }

    assertEqual(mpubkey2, mpubkey, "PublicKey")
}

func Test_KeySign(t *testing.T) {
    var hid byte = 1
    var uid = []byte("Alice")

    // ===============

    mk, err := GenerateSignMasterPrivateKey(rand.Reader)
    if err != nil {
        t.Errorf("mk gen failed:%s", err)
        return
    }

    uk, err := GenerateSignPrivateKey(mk, uid, hid)
    if err != nil {
        t.Errorf("uk gen failed:%s", err)
        return
    }

    mpk := &mk.SignMasterPublicKey

    // ===============

    mprikeyDer, err := MarshalPrivateKey(mk)
    if err != nil {
        t.Fatal(err)
    }

    if len(mprikeyDer) == 0 {
        t.Error("mprikey der make error")
    }

    mprikey2, err := ParsePrivateKey(mprikeyDer)
    if err != nil {
        t.Fatal(err)
    }

    // ===============

    prikeyDer, err := MarshalPrivateKey(uk)
    if err != nil {
        t.Fatal(err)
    }

    if len(prikeyDer) == 0 {
        t.Error("prikey der make error")
    }

    prikey2, err := ParsePrivateKey(prikeyDer)
    if err != nil {
        t.Fatal(err)
    }

    // ===============

    mpubkeyDer, err := MarshalPublicKey(mpk)
    if err != nil {
        t.Fatal(err)
    }

    if len(mpubkeyDer) == 0 {
        t.Error("pub pem make error")
    }

    mpubkey2, err := ParsePublicKey(mpubkeyDer)
    if err != nil {
        t.Fatal(err)
    }

    // ===============

    msg := []byte("message")

    mk = mprikey2.(*SignMasterPrivateKey)
    uk = prikey2.(*SignPrivateKey)
    mpk = mpubkey2.(*SignMasterPublicKey)

    h, s, err := Sign(rand.Reader, uk, msg)
    if err != nil {
        t.Errorf("sm9 sign failed:%s", err)
        return
    }

    if !Verify(mpk, uid, hid, msg, h, s) {
        t.Error("sm9 sig is invalid")
        return
    }
}

// =======

func Test_EncryptPrivateKey(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    mprikey, err := GenerateEncryptMasterPrivateKey(rand.Reader)
    if err != nil {
        t.Errorf("mprikey gen failed:%s", err)
        return
    }

    var hid byte = 1
    var uid = []byte("Alice")

    prikey, err := GenerateEncryptPrivateKey(mprikey, uid, hid)
    if err != nil {
        t.Errorf("prikey gen failed:%s", err)
        return
    }

    // ==========

    mprikeyDer, err := MarshalPrivateKey(mprikey)
    if err != nil {
        t.Fatal(err)
    }

    if len(mprikeyDer) == 0 {
        t.Error("mprikey der make error")
    }

    mprikey2, err := ParsePrivateKey(mprikeyDer)
    if err != nil {
        t.Fatal(err)
    }

    assertEqual(mprikey2.(*EncryptMasterPrivateKey).D, mprikey.D, "mprikey")

    // ==========

    prikeyDer, err := MarshalPrivateKey(prikey)
    if err != nil {
        t.Fatal(err)
    }

    if len(mprikeyDer) == 0 {
        t.Error("prikey der make error")
    }

    prikey2, err := ParsePrivateKey(prikeyDer)
    if err != nil {
        t.Fatal(err)
    }

    assertEqual(prikey2, prikey, "prikey")
}

func Test_EncryptPublicKey(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    mprikey, err := GenerateEncryptMasterPrivateKey(rand.Reader)
    if err != nil {
        t.Errorf("mprikey gen failed:%s", err)
        return
    }

    mpubkey := mprikey.PublicKey()

    mpubkeyDer, err := MarshalPublicKey(mpubkey)
    if err != nil {
        t.Fatal(err)
    }

    if len(mpubkeyDer) == 0 {
        t.Error("pub pem make error")
    }

    mpubkey2, err := ParsePublicKey(mpubkeyDer)
    if err != nil {
        t.Fatal(err)
    }

    assertEqual(mpubkey2, mpubkey, "PublicKey")
}

func Test_KeyEncrypt(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)

    var hid byte = 1
    var uid = []byte("Alice")

    // ===============

    mk, err := GenerateEncryptMasterPrivateKey(rand.Reader)
    if err != nil {
        t.Errorf("mk gen failed:%s", err)
        return
    }

    uk, err := GenerateEncryptPrivateKey(mk, uid, hid)
    if err != nil {
        t.Errorf("uk gen failed:%s", err)
        return
    }

    mpk := &mk.EncryptMasterPublicKey

    // ===============

    prikeyDer, err := MarshalPrivateKey(uk)
    if err != nil {
        t.Fatal(err)
    }

    if len(prikeyDer) == 0 {
        t.Error("prikey der make error")
    }

    prikey2, err := ParsePrivateKey(prikeyDer)
    if err != nil {
        t.Fatal(err)
    }

    // ===============

    mpubkeyDer, err := MarshalPublicKey(mpk)
    if err != nil {
        t.Fatal(err)
    }

    if len(mpubkeyDer) == 0 {
        t.Error("pub pem make error")
    }

    mpubkey2, err := ParsePublicKey(mpubkeyDer)
    if err != nil {
        t.Fatal(err)
    }

    // ===============

    msg := []byte("message")

    uk = prikey2.(*EncryptPrivateKey)
    mpk = mpubkey2.(*EncryptMasterPublicKey)

    endata, err := Encrypt(rand.Reader, mpk, uid, hid, msg, DefaultOpts)
    if err != nil {
        t.Errorf("sm9 Encrypt failed:%s", err)
        return
    }

    newMsg, err := Decrypt(uk, uid, endata, DefaultOpts)
    if err != nil {
        t.Errorf("sm9 Decrypt failed:%s", err)
        return
    }

    assert(newMsg, msg, "sm9 Decrypt failed")
}

// =======

func decodePEM(pubPEM string) *pem.Block {
    block, _ := pem.Decode([]byte(pubPEM))
    if block == nil {
        panic("failed to parse PEM block containing the key")
    }

    return block
}

func encodePEM(src []byte, typ string) string {
    keyBlock := &pem.Block{
        Type:  typ,
        Bytes: src,
    }

    keyData := pem.EncodeToMemory(keyBlock)

    return string(keyData)
}

// =======

var testSignMPriv = `
-----BEGIN SM9 SIGN MASTER PRIVATE KEY-----
MIHIAgEAMBUGCCqBHM9VAYIuBgkqgRzPVQGCLgEEgaswgagCIQCt2w7B+ssh8vR4
vOnMdO6w6o6h5Jj1SNu3In1N60REwgOBggAENxeldd01leE9ne+7EZbPUsVIXYL6
FUcqqJGJF++fJgMY5E7BBDkwMOuDJftYXaicSx408p0BBOi2iRgi+K3s77NiIwP0
T4bYhUcMNQvL1vEeTrMhik8kGIUu00Tt701Na+OiGQK4cdYfQuuyBSZDj0+cAVvy
7ueXAMrYjf9KXtI=
-----END SM9 SIGN MASTER PRIVATE KEY-----
`
var testSignPriv = `
-----BEGIN SM9 SIGN PRIVATE KEY-----
MIHhAgEAMA0GCSqBHM9VAYIuAQUABIHMMIHJA0IABFWXlXTTQH4yglrTuUKqLAaf
AvSVOTRy/jdiYtX2wvQyKfqBde6Y6BfHZT85p1PjXHeEG8IMRuDy0eAKmq7/y0oD
gYIABDcXpXXdNZXhPZ3vuxGWz1LFSF2C+hVHKqiRiRfvnyYDGOROwQQ5MDDrgyX7
WF2onEseNPKdAQTotokYIvit7O+zYiMD9E+G2IVHDDULy9bxHk6zIYpPJBiFLtNE
7e9NTWvjohkCuHHWH0LrsgUmQ49PnAFb8u7nlwDK2I3/Sl7S
-----END SM9 SIGN PRIVATE KEY-----
`
var testSignPub = `
-----BEGIN SM9 SIGN MASTER PUBLIC KEY-----
MIGgMBUGCCqBHM9VAYIuBgkqgRzPVQGCLgEDgYYAA4GCAAQ3F6V13TWV4T2d77sR
ls9SxUhdgvoVRyqokYkX758mAxjkTsEEOTAw64Ml+1hdqJxLHjTynQEE6LaJGCL4
rezvs2IjA/RPhtiFRww1C8vW8R5OsyGKTyQYhS7TRO3vTU1r46IZArhx1h9C67IF
JkOPT5wBW/Lu55cAytiN/0pe0g==
-----END SM9 SIGN MASTER PUBLIC KEY-----
`

func Test_SignKey_Check(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    mprikeyDer := decodePEM(testSignMPriv)
    mprikey, err := ParsePrivateKey(mprikeyDer.Bytes)
    assertError(err, "testSignMPriv")
    assertNotEmpty(mprikey, "testSignMPriv")

    prikeyDer := decodePEM(testSignPriv)
    prikey, err := ParsePrivateKey(prikeyDer.Bytes)
    assertError(err, "testSignPriv")
    assertNotEmpty(prikey, "testSignPriv")

    pubDer := decodePEM(testSignPub)
    mpubkey, err := ParsePublicKey(pubDer.Bytes)
    assertError(err, "testSignPub")
    assertNotEmpty(mpubkey, "testSignPub")
}

func test_KeySign11(t *testing.T) {
    var hid byte = 1
    var uid = []byte("Alice")

    msg := []byte("message")

    prikeyDer := decodePEM(testSignPriv)
    prikey, _ := ParsePrivateKey(prikeyDer.Bytes)

    uk := prikey.(*SignPrivateKey)

    pubkeyDer := decodePEM(testSignPub)
    pubkey, _ := ParsePublicKey(pubkeyDer.Bytes)

    mpk := pubkey.(*SignMasterPublicKey)

    h, s, err := Sign(rand.Reader, uk, msg)
    if err != nil {
        t.Errorf("sm9 sign failed:%s", err)
        return
    }

    if !Verify(mpk, uid, hid, msg, h, s) {
        t.Error("sm9 sig failed")
        return
    }
}

// =======

var testEncryptMPriv = `
-----BEGIN SM9 ENC MASTER PRIVATE KEY-----
MIGEAgEAMBUGCCqBHM9VAYIuBgkqgRzPVQGCLgMEaDBmAiBtTWzPz7ihVUzZQmZR
vopFejo9z97dP0Ekemaj0Go/nwNCAASwuGdlWcAXSiSCUAWGorrfg3c2uOkAJBT7
usXXIKsTU2Exj+iq8P2vvZD4ZvRs4VugzIITJ35MuVkj4D+r8lj4
-----END SM9 ENC MASTER PRIVATE KEY-----
`
var testEncryptPriv = `
-----BEGIN SM9 ENC PRIVATE KEY-----
MIHhAgEAMA0GCSqBHM9VAYIuAwUABIHMMIHJA4GCAASafuG584pfKE0K5sDXx52q
X0oZpzoMBxclSlE5lUy4V49tbssjYQ4rkdzIJWkkEeDWG52lpk8etLPRR5UUDhQB
U2pj2tfLnK5yqGKjJnkz6obwXDD+/PQZiyE2TM+NwFBFgQRKKG5adOsegWBmsd0x
MGuL6mSwILdI2P+6RSBWqANCAASwuGdlWcAXSiSCUAWGorrfg3c2uOkAJBT7usXX
IKsTU2Exj+iq8P2vvZD4ZvRs4VugzIITJ35MuVkj4D+r8lj4
-----END SM9 ENC PRIVATE KEY-----
`
var testEncryptPub = `
-----BEGIN SM9 ENC MASTER PUBLIC KEY-----
MF4wFQYIKoEcz1UBgi4GCSqBHM9VAYIuAwNFAANCAASwuGdlWcAXSiSCUAWGorrf
g3c2uOkAJBT7usXXIKsTU2Exj+iq8P2vvZD4ZvRs4VugzIITJ35MuVkj4D+r8lj4
-----END SM9 ENC MASTER PUBLIC KEY-----
`

func Test_EncryptKey_Check(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    mprikeyDer := decodePEM(testEncryptMPriv)
    mprikey, err := ParsePrivateKey(mprikeyDer.Bytes)
    assertError(err, "testEncryptMPriv")
    assertNotEmpty(mprikey, "testEncryptMPriv")

    prikeyDer := decodePEM(testEncryptPriv)
    prikey, err := ParsePrivateKey(prikeyDer.Bytes)
    assertError(err, "testEncryptPriv")
    assertNotEmpty(prikey, "testEncryptPriv")

    pubDer := decodePEM(testEncryptPub)
    mpubkey, err := ParsePublicKey(pubDer.Bytes)
    assertError(err, "testEncryptPub")
    assertNotEmpty(mpubkey, "testEncryptPub")
}

func Test_PemKeyEncrypt(t *testing.T) {
    var hid byte = 1
    var uid = []byte("Alice")

    msg := []byte("message")

    prikeyDer := decodePEM(testEncryptPriv)
    prikey, _ := ParsePrivateKey(prikeyDer.Bytes)

    uk := prikey.(*EncryptPrivateKey)

    pubkeyDer := decodePEM(testEncryptPub)
    pubkey, _ := ParsePublicKey(pubkeyDer.Bytes)

    mpk := pubkey.(*EncryptMasterPublicKey)

    en, err := Encrypt(rand.Reader, mpk, uid, hid, msg, nil)
    if err != nil {
        t.Errorf("sm9 Encrypt failed:%s", err)
        return
    }

    de, err := Decrypt(uk, uid, en, nil)
    if err != nil {
        t.Error("sm9 Decrypt failed")
        return
    }

    if string(msg) != string(de) {
        t.Error("sm9 Decrypt Check failed")
        return
    }
}

// =======

var testSignMPriv2 = `
-----BEGIN masterKey PRIVATE KEY-----
MIHHAgEAMBUGCCqBHM9VAYIuBgkqgRzPVQGCLgEEgaowgacCIBi/WYY3tscBJIAl
YocZGHNC3fnI2yLT/1zTF239Jkk+A4GCAARM5tyRCoC+sTyctT7bmBu1xECKVifx
vvx3yDiK5jp23lenV1iMCEIg9PDxmdoN7kHD0j9c2n4zSLx8hAbI4y6uGwOJ+Ylr
M/zFtPyx18IWwCNptlxK9RI5NcA5RGmda6JJNtviTaGeylKWSVp71kzLV9DCbhGN
1h05Em19ScVWnw==
-----END masterKey PRIVATE KEY-----
`
var testSignPriv2 = `
-----BEGIN userKey PRIVATE KEY-----
MIHhAgEAMA0GCSqBHM9VAYIuAQUABIHMMIHJA0IABAB2IU1ldD2E1lbElxFGsgcO
rPLg/nKjwy9byLSqO4m2ogzt4mvmrkrI+Rd2tVm/bgecB7s3PXk6LJLFZpY2uUkD
gYIABEzm3JEKgL6xPJy1PtuYG7XEQIpWJ/G+/HfIOIrmOnbeV6dXWIwIQiD08PGZ
2g3uQcPSP1zafjNIvHyEBsjjLq4bA4n5iWsz/MW0/LHXwhbAI2m2XEr1Ejk1wDlE
aZ1rokk22+JNoZ7KUpZJWnvWTMtX0MJuEY3WHTkSbX1JxVaf
-----END userKey PRIVATE KEY-----
`
var testSignPub2 = `
-----BEGIN SM9 SIGN MASTER PUBLIC KEY-----
MIGFA4GCAARM5tyRCoC+sTyctT7bmBu1xECKVifxvvx3yDiK5jp23lenV1iMCEIg
9PDxmdoN7kHD0j9c2n4zSLx8hAbI4y6uGwOJ+YlrM/zFtPyx18IWwCNptlxK9RI5
NcA5RGmda6JJNtviTaGeylKWSVp71kzLV9DCbhGN1h05Em19ScVWnw==
-----END SM9 SIGN MASTER PUBLIC KEY-----
`

func testParsePub(der []byte) []byte {
    var bytes []byte
    var inner cryptobyte.String

    input := cryptobyte.String(der)

    if !input.ReadASN1(&inner, cryptobyte_asn1.SEQUENCE) ||
            !input.Empty() ||
            !inner.ReadASN1BitStringAsBytes(&bytes) ||
            !inner.Empty() {
        return nil
    }

    return bytes
}

func Test_SignKey_Check2(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    mprikeyDer := decodePEM(testSignMPriv2)
    mprikey, err := ParsePrivateKey(mprikeyDer.Bytes)
    assertError(err, "testSignMPriv2")
    assertNotEmpty(mprikey, "testSignMPriv2")

    prikeyDer := decodePEM(testSignPriv2)
    prikey, err := ParsePrivateKey(prikeyDer.Bytes)
    assertError(err, "testSignPriv2")
    assertNotEmpty(prikey, "testSignPriv2")

    pubkeyDer := decodePEM(testSignPub2)
    pubkeyBytes := testParsePub(pubkeyDer.Bytes)

    pubkey, err := NewSignMasterPublicKey(pubkeyBytes)
    assertError(err, "testSignPub2")
    assertNotEmpty(pubkey, "testSignPub2")
}

func Test_KeySign2(t *testing.T) {
    var hid byte = 1
    var uid = []byte("testu")

    msg := []byte("message")

    prikeyDer := decodePEM(testSignPriv2)
    prikey, _ := ParsePrivateKey(prikeyDer.Bytes)

    uk := prikey.(*SignPrivateKey)

    pubkeyDer := decodePEM(testSignPub2)
    pubkeyBytes := testParsePub(pubkeyDer.Bytes)
    mpk, _ := NewSignMasterPublicKey(pubkeyBytes)

    h, s, err := Sign(rand.Reader, uk, msg)
    if err != nil {
        t.Errorf("sm9 sign failed:%s", err)
        return
    }

    if !Verify(mpk, uid, hid, msg, h, s) {
        t.Error("sm9 sig failed")
        return
    }
}

func Test_KeySign22(t *testing.T) {
    var hid byte = 1
    var uid = []byte("testu")

    msg := []byte("message")

    prikeyDer := decodePEM(testSignPriv2)
    prikey, _ := ParsePrivateKey(prikeyDer.Bytes)

    uk := prikey.(*SignPrivateKey)

    pubkeyDer := decodePEM(testSignPub2)
    pubkeyBytes := testParsePub(pubkeyDer.Bytes)
    mpk, _ := NewSignMasterPublicKey(pubkeyBytes)

    sig, err := SignASN1(rand.Reader, uk, msg)
    if err != nil {
        t.Errorf("sm9 sign failed:%s", err)
        return
    }

    // t.Errorf("%x", sig)

    if !VerifyASN1(mpk, uid, hid, msg, sig) {
        t.Error("sm9 sig failed")
        return
    }
}

func Test_SignKey_Check3(t *testing.T) {
    uid := []byte("testu")
    hid := byte(0x01)

    msg := []byte("message")

    sig := "3066042010432a7016d9a517b1bb02aa337cbe220ec99d3ac3d7bcced14425a649adfd9c0342000437fdc2838abe1c4939b64cfeec73a0d860b581b240704c089a513a0014d870724178dae3e1e30f6dad7952c9cebcb7f5b579cd1b90a6e07bfbec2a39cc169539"

    pubkeyDer := decodePEM(testSignPub2)
    pubkeyBytes := testParsePub(pubkeyDer.Bytes)
    mpk, _ := NewSignMasterPublicKey(pubkeyBytes)

    sigBytes, err := hex.DecodeString(sig)
    if err != nil {
        t.Fatal(err)
    }

    veri := VerifyASN1(mpk, uid, hid, msg, sigBytes)
    if !veri {
        t.Error("check fail")
    }
}

func Test_PemKeySignWithKey(t *testing.T) {
    var hid byte = 1
    var uid = []byte("testu")

    msg := []byte("message")

    prikeyDer := decodePEM(testSignPriv2)
    prikey, _ := ParsePrivateKey(prikeyDer.Bytes)

    uk := prikey.(*SignPrivateKey)

    pubkeyDer := decodePEM(testSignPub2)
    pubkeyBytes := testParsePub(pubkeyDer.Bytes)
    mpk, _ := NewSignMasterPublicKey(pubkeyBytes)

    sig, err := uk.Sign(rand.Reader, msg)
    if err != nil {
        t.Errorf("sm9 sign failed:%s", err)
        return
    }

    if !mpk.Verify(uid, hid, msg, sig) {
        t.Error("sm9 sig failed")
        return
    }
}

// =======

var testEncryptMPriv2 = `
-----BEGIN SM9 ENC MASTER PRIVATE KEY-----
MIGFAgEAMBUGCCqBHM9VAYIuBgkqgRzPVQGCLgMEaTBnAiEAir3bj9m5Nj8bLlNh
ag1CvlZz/W8mIh7Xx0DBEBSdZiADQgAEBKYwj40Eb6ig0GmLLCM0mOkTm+JvWp4E
eQIjwxMO2BFnAGHTY4qDKmZM/VAqRR5o6vVtXlZ3sKe7WU5rw4IcRA==
-----END SM9 ENC MASTER PRIVATE KEY-----
`
var testEncryptPriv2 = `
-----BEGIN SM9 ENC PRIVATE KEY-----
MIHhAgEAMA0GCSqBHM9VAYIuAwUABIHMMIHJA4GCAASbw8MdJY3bmIaNwtzZ52GA
H/op1Y9pfIYxb2mJLLvBd6zpRkN0NtrO3QQ+piiD4zEHOB7ovqtaZ6BZ9GDQdLay
TtW3uF0vfzTE/0YOLsTkUJGYvAYUC8UgC7oEdnn5tVYzG80KU5ReWed3LxUJewe9
3hDoNImjex1nRtaHHCfBJQNCAAQEpjCPjQRvqKDQaYssIzSY6ROb4m9angR5AiPD
Ew7YEWcAYdNjioMqZkz9UCpFHmjq9W1eVnewp7tZTmvDghxE
-----END SM9 ENC PRIVATE KEY-----
`
var testEncryptPub2 = `
-----BEGIN SM9 ENC MASTER PUBLIC KEY-----
MEQDQgAEBKYwj40Eb6ig0GmLLCM0mOkTm+JvWp4EeQIjwxMO2BFnAGHTY4qDKmZM
/VAqRR5o6vVtXlZ3sKe7WU5rw4IcRA==
-----END SM9 ENC MASTER PUBLIC KEY-----
`

func Test_EncryptKey_Check2(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    mprikeyDer := decodePEM(testEncryptMPriv2)
    mprikey, err := ParsePrivateKey(mprikeyDer.Bytes)
    assertError(err, "testEncryptMPriv2")
    assertNotEmpty(mprikey, "testEncryptMPriv2")

    prikeyDer := decodePEM(testEncryptPriv2)
    prikey, err := ParsePrivateKey(prikeyDer.Bytes)
    assertError(err, "testEncryptPriv2")
    assertNotEmpty(prikey, "testEncryptPriv2")

    pubkeyDer := decodePEM(testEncryptPub2)
    pubkeyBytes := testParsePub(pubkeyDer.Bytes)

    pubkey, err := NewEncryptMasterPublicKey(pubkeyBytes)
    assertNotEmpty(pubkey, "testEncryptPub2")
}

func Test_PemKeyEncrypt2(t *testing.T) {
    uid := []byte("testu")
    hid := byte(0x01)

    msg := []byte("message")

    prikeyDer := decodePEM(testEncryptPriv2)
    prikey, _ := ParsePrivateKey(prikeyDer.Bytes)

    uk := prikey.(*EncryptPrivateKey)

    pubkeyDer := decodePEM(testEncryptPub2)
    pubkeyBytes := testParsePub(pubkeyDer.Bytes)

    mpk, err := NewEncryptMasterPublicKey(pubkeyBytes)
    if err != nil {
        t.Errorf("sm9 NewEncryptMasterPublicKey failed:%s", err)
        return
    }

    en, err := Encrypt(rand.Reader, mpk, uid, hid, msg, nil)
    if err != nil {
        t.Errorf("sm9 Encrypt failed:%s", err)
        return
    }

    de, err := Decrypt(uk, uid, en, nil)
    if err != nil {
        t.Error("sm9 Decrypt failed")
        return
    }

    if string(msg) != string(de) {
        t.Error("sm9 Decrypt Check failed")
        return
    }
}

func Test_PemKeyEncrypt_ASN12(t *testing.T) {
    uid := []byte("testu")
    hid := byte(0x01)

    msg := []byte("message")

    prikeyDer := decodePEM(testEncryptPriv2)
    prikey, _ := ParsePrivateKey(prikeyDer.Bytes)

    uk := prikey.(*EncryptPrivateKey)

    pubkeyDer := decodePEM(testEncryptPub2)
    pubkeyBytes := testParsePub(pubkeyDer.Bytes)

    mpk, err := NewEncryptMasterPublicKey(pubkeyBytes)
    if err != nil {
        t.Errorf("sm9 NewEncryptMasterPublicKey failed:%s", err)
        return
    }

    en, err := EncryptASN1(rand.Reader, mpk, uid, hid, msg, nil)
    if err != nil {
        t.Errorf("sm9 EncryptASN1 failed:%s", err)
        return
    }

    // t.Errorf("%x", en)

    de, err := DecryptASN1(uk, uid, en, nil)
    if err != nil {
        t.Error("sm9 DecryptASN1 failed")
        return
    }

    if string(msg) != string(de) {
        t.Error("sm9 DecryptASN1 Check failed")
        return
    }
}

func Test_EncryptKey_Check3(t *testing.T) {
    uid := []byte("testu")

    msg := []byte("message")

    en := "30818b020102034200047fd55a36613bf4acd2144a33ff169f923fb1b258efe53a3466d73ce93d0b65d0a7f416ac7b5ac1ea4b1e288f1abcc0ced6fb08c5e27641cf6e9b3d3012c5c60f042044245fdf01c40a4dee956af78a813428dcfc22b762558905e3c03d3f052d4e1a042021347c448d38ef20bbda3e1ba3d781b1cef92930a07d1b3a939a761c36244aef"

    enBytes, err := hex.DecodeString(en)
    if err != nil {
        t.Fatal(err)
    }

    prikeyDer := decodePEM(testEncryptPriv2)
    prikey, _ := ParsePrivateKey(prikeyDer.Bytes)

    uk := prikey.(*EncryptPrivateKey)

    de, err := DecryptASN1(uk, uid, enBytes, nil)
    if err != nil {
        t.Error("sm9 DecryptASN1 2 failed。" + err.Error())
        return
    }

    if string(msg) != string(de) {
        t.Error("sm9 DecryptASN1 2 Check failed")
        return
    }
}

func Test_PemKeyEncrypt_List(t *testing.T) {
    test_PemKeyEncrypt_List(t, SM4ECBEncrypt)
    test_PemKeyEncrypt_List(t, SM4CBCEncrypt)
    test_PemKeyEncrypt_List(t, SM4CFBEncrypt)
    test_PemKeyEncrypt_List(t, SM4OFBEncrypt)
    test_PemKeyEncrypt_List(t, XorEncrypt)
}

func test_PemKeyEncrypt_List(t *testing.T, enc IEncrypt) {
    uid := []byte("testu")
    hid := byte(0x01)

    msg := []byte("message")

    prikeyDer := decodePEM(testEncryptPriv2)
    prikey, _ := ParsePrivateKey(prikeyDer.Bytes)

    uk := prikey.(*EncryptPrivateKey)

    pubkeyDer := decodePEM(testEncryptPub2)
    pubkeyBytes := testParsePub(pubkeyDer.Bytes)

    mpk, err := NewEncryptMasterPublicKey(pubkeyBytes)
    if err != nil {
        t.Errorf("sm9 NewEncryptMasterPublicKey failed:%s", err)
        return
    }

    en, err := mpk.Encrypt(rand.Reader, uid, hid, msg, enc)
    if err != nil {
        t.Errorf("sm9 Encrypt failed:%s", err)
        return
    }

    de, err := uk.Decrypt(uid, en)
    if err != nil {
        t.Error("sm9 Decrypt failed")
        return
    }

    if string(msg) != string(de) {
        t.Error("sm9 Decrypt Check failed")
        return
    }
}

