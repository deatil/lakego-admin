package sm9

import (
    "testing"
    "crypto/rand"
    "encoding/pem"

    "golang.org/x/crypto/cryptobyte"
    cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

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
MIHHAgEAMBUGCCqBHM9VAYIuBgkqgRzPVQGCLgEEgaowgacCICtbBRb0O9SCG2cX
D6+UtZtVDWAKW95rYML8pBDHHazbA4GCAAQ+hUc/GJ2U8o4e+LBZJdGOd2ChZRx6
b46ND5hd1J3YPlbceUO/ejTt0GAXa78jauFtG9AbJ4BqR+NvOm2aqxyXKJ2bULfs
gmEe5JY5m3fRrLlO8Jz1oujlPLNVzIEBhpyGEIZzd4bASwQtozmdEntzegC0+jyL
fH/qEL35lcMIWQ==
-----END SM9 SIGN MASTER PRIVATE KEY-----
`
var testSignPriv = `
-----BEGIN SM9 SIGN PRIVATE KEY-----
MIHhAgEAMA0GCSqBHM9VAYIuAQUABIHMMIHJA0IABFO5VsT5d5fdnr00YC94Mtko
Ggz59kI6zhhQ17y+ej4rjpXJi5ajoCr/cjHCEO0bmJ/qTXWF8BbdP00Mqr9o8NMD
gYIABD6FRz8YnZTyjh74sFkl0Y53YKFlHHpvjo0PmF3Undg+Vtx5Q796NO3QYBdr
vyNq4W0b0BsngGpH4286bZqrHJconZtQt+yCYR7kljmbd9GsuU7wnPWi6OU8s1XM
gQGGnIYQhnN3hsBLBC2jOZ0Se3N6ALT6PIt8f+oQvfmVwwhZ
-----END SM9 SIGN PRIVATE KEY-----
`
var testSignPub = `
-----BEGIN SM9 SIGN MASTER PUBLIC KEY-----
MIGgMBUGCCqBHM9VAYIuBgkqgRzPVQGCLgEDgYYAA4GCAAQ+hUc/GJ2U8o4e+LBZ
JdGOd2ChZRx6b46ND5hd1J3YPlbceUO/ejTt0GAXa78jauFtG9AbJ4BqR+NvOm2a
qxyXKJ2bULfsgmEe5JY5m3fRrLlO8Jz1oujlPLNVzIEBhpyGEIZzd4bASwQtozmd
EntzegC0+jyLfH/qEL35lcMIWQ==
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

func Test_KeySign11(t *testing.T) {
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
MIGFAgEAMBUGCCqBHM9VAYIuBgkqgRzPVQGCLgMEaTBnAiEAoWPTk9AwPEYbWvjs
k+ivG7nzJte256RJioDznqYyJZMDQgAERN3hxGNZNV2DtxJI6mY7s58FZejZZbgV
b4tCFRaLb5tCnXbWmjS3kxHrZiFAAJLlKD5DLUPdCfe8AjKj18iVDg==
-----END SM9 ENC MASTER PRIVATE KEY-----
`
var testEncryptPriv = `
-----BEGIN SM9 ENC PRIVATE KEY-----
MIHhAgEAMA0GCSqBHM9VAYIuAwUABIHMMIHJA4GCAAQccF3iDRg2oHMVOyd3Z4Z5
HYL6RZ1dDq9aJYkPcmb4cAYMcDxFGSJlRo8AjPwKlnqSmnVj3UK1OXrhLRSuMT2h
VK8gODBfeIvMg7V9KaocSiY5b4rhA6tYUOat7Ec8LTZ9QvNqqYczcb+3B61ZW5yP
5+U2AtKpV1fSg3rFvbOUwgNCAARE3eHEY1k1XYO3EkjqZjuznwVl6NlluBVvi0IV
Fotvm0KddtaaNLeTEetmIUAAkuUoPkMtQ90J97wCMqPXyJUO
-----END SM9 ENC PRIVATE KEY-----
`
var testEncryptPub = `
-----BEGIN SM9 ENC MASTER PUBLIC KEY-----
MF4wFQYIKoEcz1UBgi4GCSqBHM9VAYIuAwNFAANCAARE3eHEY1k1XYO3EkjqZjuz
nwVl6NlluBVvi0IVFotvm0KddtaaNLeTEetmIUAAkuUoPkMtQ90J97wCMqPXyJUO
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

func test_KeySign2(t *testing.T) {
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
