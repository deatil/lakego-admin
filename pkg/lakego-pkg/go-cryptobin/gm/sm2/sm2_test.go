package sm2_test

import (
    "bytes"
    "reflect"
    "testing"
    "math/big"
    "crypto/rand"
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "encoding/pem"
    "encoding/hex"
    "encoding/base64"

    "github.com/deatil/go-cryptobin/gm/sm2"
    "github.com/deatil/go-cryptobin/hash/sm3"
)

func decodePEM(pubPEM string) *pem.Block {
    block, _ := pem.Decode([]byte(pubPEM))
    if block == nil {
        panic("failed to parse PEM block containing the key")
    }

    return block
}

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

func Test_Sm2(t *testing.T) {
    priv, err := sm2.GenerateKey(rand.Reader) // 生成密钥对
    if err != nil {
        t.Fatal(err)
    }

    if !priv.Curve.IsOnCurve(priv.X, priv.Y) {
        t.Error("GenerateKey not Curve")
    }
}

func BenchmarkSM2(t *testing.B) {
    t.ReportAllocs()
    msg := []byte("test")
    priv, err := sm2.GenerateKey(nil) // 生成密钥对
    if err != nil {
        t.Fatal(err)
    }

    t.ResetTimer()
    for i := 0; i < t.N; i++ {
        sign, err := priv.Sign(nil, msg, nil) // 签名
        if err != nil {
            t.Fatal(err)
        }
        priv.Verify(msg, sign, nil) // 密钥验证
    }
}

func TestKEB2(t *testing.T) {
    ida := []byte{'1', '2', '3', '4', '5', '6', '7', '8',
        '1', '2', '3', '4', '5', '6', '7', '8'}
    idb := []byte{'1', '2', '3', '4', '5', '6', '7', '8',
        '1', '2', '3', '4', '5', '6', '7', '8'}
    daBuf := []byte{0x81, 0xEB, 0x26, 0xE9, 0x41, 0xBB, 0x5A, 0xF1,
        0x6D, 0xF1, 0x16, 0x49, 0x5F, 0x90, 0x69, 0x52,
        0x72, 0xAE, 0x2C, 0xD6, 0x3D, 0x6C, 0x4A, 0xE1,
        0x67, 0x84, 0x18, 0xBE, 0x48, 0x23, 0x00, 0x29}
    dbBuf := []byte{0x78, 0x51, 0x29, 0x91, 0x7D, 0x45, 0xA9, 0xEA,
        0x54, 0x37, 0xA5, 0x93, 0x56, 0xB8, 0x23, 0x38,
        0xEA, 0xAD, 0xDA, 0x6C, 0xEB, 0x19, 0x90, 0x88,
        0xF1, 0x4A, 0xE1, 0x0D, 0xEF, 0xA2, 0x29, 0xB5}
    raBuf := []byte{0xD4, 0xDE, 0x15, 0x47, 0x4D, 0xB7, 0x4D, 0x06,
        0x49, 0x1C, 0x44, 0x0D, 0x30, 0x5E, 0x01, 0x24,
        0x00, 0x99, 0x0F, 0x3E, 0x39, 0x0C, 0x7E, 0x87,
        0x15, 0x3C, 0x12, 0xDB, 0x2E, 0xA6, 0x0B, 0xB3}

    rbBuf := []byte{0x7E, 0x07, 0x12, 0x48, 0x14, 0xB3, 0x09, 0x48,
        0x91, 0x25, 0xEA, 0xED, 0x10, 0x11, 0x13, 0x16,
        0x4E, 0xBF, 0x0F, 0x34, 0x58, 0xC5, 0xBD, 0x88,
        0x33, 0x5C, 0x1F, 0x9D, 0x59, 0x62, 0x43, 0xD6}

    expk := []byte{0x6C, 0x89, 0x34, 0x73, 0x54, 0xDE, 0x24, 0x84,
        0xC6, 0x0B, 0x4A, 0xB1, 0xFD, 0xE4, 0xC6, 0xE5}

    curve := sm2.P256()
    curve.ScalarBaseMult(daBuf)
    da := new(sm2.PrivateKey)
    da.PublicKey.Curve = curve
    da.D = new(big.Int).SetBytes(daBuf)
    da.PublicKey.X, da.PublicKey.Y = curve.ScalarBaseMult(daBuf)

    db := new(sm2.PrivateKey)
    db.PublicKey.Curve = curve
    db.D = new(big.Int).SetBytes(dbBuf)
    db.PublicKey.X, db.PublicKey.Y = curve.ScalarBaseMult(dbBuf)

    ra := new(sm2.PrivateKey)
    ra.PublicKey.Curve = curve
    ra.D = new(big.Int).SetBytes(raBuf)
    ra.PublicKey.X, ra.PublicKey.Y = curve.ScalarBaseMult(raBuf)

    rb := new(sm2.PrivateKey)
    rb.PublicKey.Curve = curve
    rb.D = new(big.Int).SetBytes(rbBuf)
    rb.PublicKey.X, rb.PublicKey.Y = curve.ScalarBaseMult(rbBuf)

    k1, Sb, S2, err := sm2.KeyExchangeB(16, ida, idb, db, &da.PublicKey, rb, &ra.PublicKey)
    if err != nil {
        t.Error(err)
    }
    k2, S1, Sa, err := sm2.KeyExchangeA(16, ida, idb, da, &db.PublicKey, ra, &rb.PublicKey)
    if err != nil {
        t.Error(err)
    }
    if bytes.Compare(k1, k2) != 0 {
        t.Error("key exchange differ")
    }
    if bytes.Compare(k1, expk) != 0 {
        t.Errorf("expected %x, found %x", expk, k1)
    }
    if bytes.Compare(S1, Sb) != 0 {
        t.Error("hash verfication failed")
    }
    if bytes.Compare(Sa, S2) != 0 {
        t.Error("hash verfication failed")
    }
}

func Test_Compress(t *testing.T) {
    priv, err := sm2.GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    pk := sm2.Compress(pub)

    newpub, err := sm2.Decompress(pk)
    if err != nil {
        t.Fatal(err)
    }

    if !newpub.Equal(pub) {
        t.Errorf("Compress got %x", pk)
    }
}

func Test_SignASN1(t *testing.T) {
    priv, err := sm2.GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    msg := []byte("test-passstest-passstest-passstest-passstest-passstest-passstest-passstest-passs")

    signed, err := priv.Sign(rand.Reader, msg, nil)
    if err != nil {
        t.Error(err)
    }

    veri := pub.Verify(msg, signed, nil)
    if !veri {
        t.Error("veri error")
    }
}

func Test_SignASN1_WithUID(t *testing.T) {
    priv, err := sm2.GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    opt := sm2.SignerOpts{Uid: []byte("N002362537000000")}

    msg := []byte("test-passstest-passstest-passstest-passstest-passstest-passstest-passstest-passs")

    signed, err := priv.Sign(rand.Reader, msg, opt)
    if err != nil {
        t.Error(err)
    }

    veri := pub.Verify(msg, signed, opt)
    if !veri {
        t.Error("veri error")
    }
}

func Test_SignBytes(t *testing.T) {
    priv, err := sm2.GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    msg := []byte("test-passstest-passstest-passstest-passstest-passstest-passstest-passstest-passs")

    signed, err := priv.SignBytes(rand.Reader, msg, nil)
    if err != nil {
        t.Error(err)
    }

    veri := pub.VerifyBytes(msg, signed, nil)
    if !veri {
        t.Error("veri error")
    }
}

func Test_SignBytes_Func(t *testing.T) {
    priv, err := sm2.GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    msg := []byte("test-passstest-passstest-passstest-passstest-passstest-passstest-passstest-passs")

    signed, err := sm2.SignBytes(rand.Reader, priv, msg, nil)
    if err != nil {
        t.Error(err)
    }

    ok := sm2.VerifyBytes(pub, msg, signed, nil)
    if !ok {
        t.Error("veri error")
    }
}

func Test_SignBytes_WithUID(t *testing.T) {
    priv, err := sm2.GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    opt := sm2.SignerOpts{Uid: []byte("N002362537000000")}

    msg := []byte("test-passstest-passstest-passstest-passstest-passstest-passstest-passstest-passs")

    signed, err := priv.SignBytes(rand.Reader, msg, opt)
    if err != nil {
        t.Error(err)
    }

    veri := pub.VerifyBytes(msg, signed, opt)
    if !veri {
        t.Error("veri error")
    }
}

func Test_Sign(t *testing.T) {
    priv, err := sm2.GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    msg := []byte("test-passstest-passstest-passstest-passstest-passstest-passstest-passstest-passs")

    signed, err := priv.Sign(rand.Reader, msg, nil)
    if err != nil {
        t.Error(err)
    }

    veri := pub.Verify(msg, signed, nil)
    if !veri {
        t.Error("veri error")
    }
}

var testPrikey = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgBh/5ZbHdkwXhwteN
OYecASnP778U0BLZ4suYZf5XvIOhRANCAASQ2AGZRgNjUwkiujPI24Abec5HM1MK
ghJ+FA8z/WrZyNjgBKEV1Fm7SiVfoIuaKIGHPFm1vbkKNCqpPijXWPcM
-----END PRIVATE KEY-----
`
var testPubkey = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEkNgBmUYDY1MJIrozyNuAG3nORzNT
CoISfhQPM/1q2cjY4AShFdRZu0olX6CLmiiBhzxZtb25CjQqqT4o11j3DA==
-----END PUBLIC KEY-----
`

func Test_Encrypt(t *testing.T) {
    blockPri := decodePEM(testPrikey)
    pri, err := sm2.ParsePrivateKey(blockPri.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    blockPub := decodePEM(testPubkey)
    pub, err := sm2.ParsePublicKey(blockPub.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    plainText := "sm2-data"

    ciphertext, err := sm2.Encrypt(rand.Reader, pub, []byte(plainText), sm2.EncrypterOpts{
        Mode: sm2.C1C3C2,
    })
    if err != nil {
        t.Fatalf("encrypt failed %v", err)
    }

    plaintext, err := pri.Decrypt(rand.Reader, ciphertext, sm2.EncrypterOpts{
        Mode: sm2.C1C3C2,
    })
    if err != nil {
        t.Fatalf("decrypt failed %v", err)
    }

    if !reflect.DeepEqual(string(plaintext), plainText) {
        t.Errorf("Decrypt() = %v, want %v", string(plaintext), plainText)
    }
}

func Test_Encrypt_C1C2C3(t *testing.T) {
    blockPri := decodePEM(testPrikey)
    pri, err := sm2.ParsePrivateKey(blockPri.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    blockPub := decodePEM(testPubkey)
    pub, err := sm2.ParsePublicKey(blockPub.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    plainText := "sm2-data"

    ciphertext, err := sm2.Encrypt(rand.Reader, pub, []byte(plainText), sm2.EncrypterOpts{
        Mode: sm2.C1C2C3,
    })
    if err != nil {
        t.Fatalf("encrypt failed %v", err)
    }

    plaintext, err := pri.Decrypt(rand.Reader, ciphertext, sm2.EncrypterOpts{
        Mode: sm2.C1C2C3,
    })
    if err != nil {
        t.Fatalf("decrypt failed %v", err)
    }

    if !reflect.DeepEqual(string(plaintext), plainText) {
        t.Errorf("Decrypt() = %v, want %v", string(plaintext), plainText)
    }
}

func Test_EncryptASN1_Check(t *testing.T) {
    blockPri := decodePEM(testPrikey)
    pri, err := sm2.ParsePrivateKey(blockPri.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    msg := []byte("test-passstest-passstest-passstest-passstest-passs")
    endata := "30819a0220332155fdbbbbad9b408f124d890fe8a77de816c2f56b7c196c537525519aa88f02206c5fb12491d4fededdb2abe0618951b7825d44671fbb3eb80f9a02a5c40bf8fa0420ba308604554043a51f9914677ec42a1728abeaa85c98b58260cb4ab7518c3dd8043263cbcad8c6034f02377aeedde68f65e4675caf4bb934845949d77d5dfca24d774996fd1de48a93378abbe07f312ffcd6f228"

    en, _ := hex.DecodeString(endata)

    dedata, err := pri.DecryptASN1(en, nil)
    if err != nil {
        t.Fatal(err)
    }

    if bytes.Compare(msg, dedata) != 0 {
        t.Error("DecryptAsn1 error")
    }
}

func Test_Sign_Check(t *testing.T) {
    blockPub := decodePEM(testPubkey)
    pub, err := sm2.ParsePublicKey(blockPub.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    msg := []byte("test-passstest-passstest-passstest-passstest-passs")
    uid := []byte("098765b4312345678")

    sign := "30460221008a85349a2b649da6607c6c31f30f6279dd18fc74aa77e41430114019bf58fc09022100f7080d52119721450874d5ab76cd26ebf2c7164250dac6f5fceb08bbc30b5230"

    design, _ := hex.DecodeString(sign)

    if !pub.Verify(msg, design, sm2.SignerOpts{
        Uid: uid,
    }) {
        t.Error("Verify error")
    }
}

func Test_NewPrivateKey(t *testing.T) {
    priv, err := sm2.GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    privHex := sm2.PrivateKeyTo(priv)
    priv2, err := sm2.NewPrivateKey(privHex)
    if err != nil {
        t.Fatal(err)
    }

    if !priv2.Equal(priv) {
        t.Error("NewPrivateKey Equal error")
    }

    // ======

    pub := &priv.PublicKey

    pubHex := sm2.PublicKeyTo(pub)
    pub2, err := sm2.NewPublicKey(pubHex)
    if err != nil {
        t.Fatal(err)
    }

    if !pub2.Equal(pub) {
        t.Error("NewPublicKey Equal error")
    }
}

var testPrikey2 = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQga0uyz+bU40mfdM/QWwSLOAIw1teD
frvhqGWFAFT7r9uhRANCAATsU4K/XvtvANt0yF+eSabtX20tNXCMfaVMSmV7iq4gGxJKXppqIObD
ccNE4TCP1uA7VyFgARYRXKGzV/eMSx17
-----END PRIVATE KEY-----
`

func Test_Encrypt_Check2(t *testing.T) {
    blockPri := decodePEM(testPrikey2)
    pri, err := sm2.ParsePrivateKey(blockPri.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    msg := []byte("123")
    endata := "MGwCIQDafQBon8ZrC5fRya4oC6yAgONN6PIWN/I4fk/8wwhGIAIgJgJ/vmW0UmEGmzTp4sgPvigyafQXSU5gsfwLJvE1WYwEIM8nvAb2K7xoK/Q/yi7z/7jzq5XwO3/TtDyvluEiZD0yBAP1Ed4="

    en, _ := base64.StdEncoding.DecodeString(endata)

    dedata, err := pri.DecryptASN1(en, nil)
    if err != nil {
        t.Fatal(err)
    }

    if bytes.Compare(msg, dedata) != 0 {
        t.Errorf("Encrypt_Check2 DecryptAsn1 error: got %s, want %s", string(dedata), string(msg))
    }
}

func Test_SignSha256WithSM2(t *testing.T) {
    priv, err := sm2.GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    var defaultUID = []byte{
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    }

    msg := []byte("test-passstest-passstest-passstest-passstest-passstest-passstest-passstest-passs")

    r, s, err := sm2.SignToRS(rand.Reader, priv, msg, sm2.SignerOpts{
        Uid:  defaultUID,
        Hash: sha256.New,
    })
    if err != nil {
        t.Error(err)
    }

    ok := sm2.VerifyWithRS(pub, msg, r, s, sm2.SignerOpts{
        Uid:  defaultUID,
        Hash: sha256.New,
    })
    if !ok {
        t.Error("veri error")
    }
}

func Test_SignSM3Digest_Check(t *testing.T) {
    uid := "sm2test@example.com"
    msg := "hi chappy"
    x := "110E7973206F68C19EE5F7328C036F26911C8C73B4E4F36AE3291097F8984FFC"
    r := "05890B9077B92E47B17A1FF42A814280E556AFD92B4A98B9670BF8B1A274C2FA"
    s := "E3ABBB8DB2B6ECD9B24ECCEA7F679FB9A4B1DB52F4AA985E443AD73237FA1993"

    xb, _ := hex.DecodeString(x)
    rr, _ := new(big.Int).SetString(r, 16)
    ss, _ := new(big.Int).SetString(s, 16)

    priv, err := sm2.NewPrivateKey(xb)
    if err != nil {
        t.Fatal(err)
    }
    pub := &priv.PublicKey

    ok := sm2.VerifyWithRS(pub, []byte(msg), rr, ss, sm2.SignerOpts{
        Uid: []byte(uid),
    })
    if !ok {
        t.Error("veri error")
    }

}

func Test_SignSHA256Digest_Check(t *testing.T) {
    uid := "sm2test@example.com"
    msg := "hi chappy"
    x := "110E7973206F68C19EE5F7328C036F26911C8C73B4E4F36AE3291097F8984FFC"
    r := "94DA20EA69E4FC70692158BF3D30F87682A4B2F84DF4A4829A1EFC5D9C979D3F"
    s := "EE15AF8D455B728AB80E592FCB654BF5B05620B2F4D25749D263D5C01FAD365F"

    xb, _ := hex.DecodeString(x)
    rr, _ := new(big.Int).SetString(r, 16)
    ss, _ := new(big.Int).SetString(s, 16)

    priv, err := sm2.NewPrivateKey(xb)
    if err != nil {
        t.Fatal(err)
    }
    pub := &priv.PublicKey

    ok := sm2.VerifyWithRS(pub, []byte(msg), rr, ss, sm2.SignerOpts{
        Uid:  []byte(uid),
        Hash: sha256.New,
    })
    if !ok {
        t.Error("veri error")
    }

}

var testPrikey3 = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQga0uyz+bU40mfdM/QWwSLOAIw1teD
frvhqGWFAFT7r9uhRANCAATsU4K/XvtvANt0yF+eSabtX20tNXCMfaVMSmV7iq4gGxJKXppqIObD
ccNE4TCP1uA7VyFgARYRXKGzV/eMSx17
-----END PRIVATE KEY-----
`
var testPubkey3 = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE7FOCv177bwDbdMhfnkmm7V9tLTVw
jH2lTEple4quIBsSSl6aaiDmw3HDROEwj9bgO1chYAEWEVyhs1f3jEsdew==
-----END PUBLIC KEY-----
`

func Test_EncryptSM3_Check(t *testing.T) {
    blockPri := decodePEM(testPrikey3)
    pri, err := sm2.ParsePrivateKey(blockPri.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    msg := []byte("testtest123123")
    endata := "BBbcwtq8K+ZxxUnFv2LF3QkUALtMrh+ZFVAMcKm/PQhG1pgvmmlHdxQ/JX3wGuJuzspC5vWZUziNfgS1+kOukU5QkkHJ+ooiwoIw/MubDFBXvHCoAVdlo1EbeYUyeOnd07jSeu45VxjM+dJypJK/"

    en, _ := base64.StdEncoding.DecodeString(endata)

    dedata, err := pri.Decrypt(rand.Reader, en, sm2.EncrypterOpts{
        Mode: sm2.C1C3C2,
        Hash: sm3.New,
    })
    if err != nil {
        t.Fatal(err)
    }

    if bytes.Compare(msg, dedata) != 0 {
        t.Errorf("Test_EncryptSM3_Check Decrypt error: got %s, want %s", string(dedata), string(msg))
    }
}

func Test_EncryptMD5_Check(t *testing.T) {
    blockPri := decodePEM(testPrikey3)
    pri, err := sm2.ParsePrivateKey(blockPri.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    msg := []byte("testtest123123")
    endata := "BMPd85Lwg8ovJ0QScoD+N1y0TZ65nCqtY7kvCZTDEMa2xv6d6PcjKbN+xS2wcvDKWslXNHm0N5jidvR7puqyqAdhWm1u/xw3OF5A7BWreG/m7mnlDYViXpXcFPWCdP0="

    en, _ := base64.StdEncoding.DecodeString(endata)

    dedata, err := pri.Decrypt(rand.Reader, en, sm2.EncrypterOpts{
        Mode: sm2.C1C3C2,
        Hash: md5.New,
    })
    if err != nil {
        t.Fatal(err)
    }

    if bytes.Compare(msg, dedata) != 0 {
        t.Errorf("Test_EncryptMD5_Check Decrypt error: got %s, want %s", string(dedata), string(msg))
    }
}

func Test_EncryptSha1_Check(t *testing.T) {
    blockPri := decodePEM(testPrikey3)
    pri, err := sm2.ParsePrivateKey(blockPri.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    msg := []byte("testtest123123")
    endata := "BPSJaSfjaR5hy1mN6G5pVYXVbgzl0xo6YcCbxkrJgC91s2yLSBdDXcr+kJH6LTTCJ7wIb6M7xMn/lZslrzlGOsLV1uiFr9uHnI2p91GEbttKJ+8hE8Luiwb8gzB5DF4wDLee"

    en, _ := base64.StdEncoding.DecodeString(endata)

    dedata, err := pri.Decrypt(rand.Reader, en, sm2.EncrypterOpts{
        Mode: sm2.C1C3C2,
        Hash: sha1.New,
    })
    if err != nil {
        t.Fatal(err)
    }

    if bytes.Compare(msg, dedata) != 0 {
        t.Errorf("Test_EncryptSha1_Check Decrypt error: got %s, want %s", string(dedata), string(msg))
    }
}

func Test_EncryptSha256_Check(t *testing.T) {
    blockPri := decodePEM(testPrikey3)
    pri, err := sm2.ParsePrivateKey(blockPri.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    msg := []byte("testtest123123")
    endata := "BF7X/kRsh3N9YWdYKBlVBRZXwVO79IocLQS6a69B5Gch9bbZf8jjqZnVLPdC9Dh21/HqLNDd1tjuu8VnHJFyp3soUCgN94A9+BWt1Uy6+uZuQXFcZHfVqyw/7tXMKtDVEV2aKodne7Boc7RZ0bO4"

    en, _ := base64.StdEncoding.DecodeString(endata)

    dedata, err := pri.Decrypt(rand.Reader, en, sm2.EncrypterOpts{
        Mode: sm2.C1C3C2,
        Hash: sha256.New,
    })
    if err != nil {
        t.Fatal(err)
    }

    if bytes.Compare(msg, dedata) != 0 {
        t.Errorf("Test_EncryptSha256_Check Decrypt error: got %s, want %s", string(dedata), string(msg))
    }
}

func Test_EncryptSM3_C1C2C3_Check(t *testing.T) {
    blockPri := decodePEM(testPrikey3)
    pri, err := sm2.ParsePrivateKey(blockPri.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    msg := []byte("testtest123123")
    endata := "BDyaPy9dvXUL7FNcnos/lsxC6wVES8C3UcHX4ZLQTxq70fRFrHytdCREwvwY7A1Gb7bhJ98GHiLIHh/xasRlkRaAaTnZ/f2mXZwE5E5hcTvYk+0QY69vq3EQ7RPDqEoCKo92ssFs7n/0rySUq3fC"

    en, _ := base64.StdEncoding.DecodeString(endata)

    dedata, err := pri.Decrypt(rand.Reader, en, sm2.EncrypterOpts{
        Mode: sm2.C1C2C3,
        Hash: sm3.New,
    })
    if err != nil {
        t.Fatal(err)
    }

    if bytes.Compare(msg, dedata) != 0 {
        t.Errorf("Test_EncryptSM3_C1C2C3_Check Decrypt error: got %s, want %s", string(dedata), string(msg))
    }
}

func Test_EncryptMD5_C1C2C3_Check(t *testing.T) {
    blockPri := decodePEM(testPrikey3)
    pri, err := sm2.ParsePrivateKey(blockPri.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    msg := []byte("testtest123123")
    endata := "BILXsGbOu0caMK2MDh8Jp47js3xJcJLbWh+lNTGmaf/8+fslZXY0ZwLkXJrKKpzGlrJdh8+xlFfeTWNYimjq/GETzNvp3TgUcLvy1+l7VYY5Y8NhU21SjRa2gp1llZ8="

    en, _ := base64.StdEncoding.DecodeString(endata)

    dedata, err := pri.Decrypt(rand.Reader, en, sm2.EncrypterOpts{
        Mode: sm2.C1C2C3,
        Hash: md5.New,
    })
    if err != nil {
        t.Fatal(err)
    }

    if bytes.Compare(msg, dedata) != 0 {
        t.Errorf("Test_EncryptMD5_C1C2C3_Check Decrypt error: got %s, want %s", string(dedata), string(msg))
    }
}

func Test_EncryptSha1_C1C2C3_Check(t *testing.T) {
    blockPri := decodePEM(testPrikey3)
    pri, err := sm2.ParsePrivateKey(blockPri.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    msg := []byte("testtest123123")
    endata := "BAkkBNj2s8ajNlBMcLxxdxvyByX+hV8PFv2qFpjcJe2Casw/L/UZG7zZHA4bS43OKmveqvRsyFXgQDKFdqIBGfZEk+Ixy5lqmE/VrNZnOKi81YKQAqXYhhLpA8KrK/9r+yHB"

    en, _ := base64.StdEncoding.DecodeString(endata)

    dedata, err := pri.Decrypt(rand.Reader, en, sm2.EncrypterOpts{
        Mode: sm2.C1C2C3,
        Hash: sha1.New,
    })
    if err != nil {
        t.Fatal(err)
    }

    if bytes.Compare(msg, dedata) != 0 {
        t.Errorf("Test_EncryptSha1_C1C2C3_Check Decrypt error: got %s, want %s", string(dedata), string(msg))
    }
}

func Test_EncryptSha256_C1C2C3_Check(t *testing.T) {
    blockPri := decodePEM(testPrikey3)
    pri, err := sm2.ParsePrivateKey(blockPri.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    msg := []byte("testtest123123")
    endata := "BAT4sgpHYBpBKI/8uwCX3zSLh5YoJxslDoK9V1jzLFMY4wj0ZCfr49vvan+s6LYQRmdmY92bXpHKjGGWAGISitvnm+qHWc0ubnEGpL/+DJhrPt5tQ17Ui25LXdf4EwA68i1GEsTZ4p6RpAGnysmn"

    en, _ := base64.StdEncoding.DecodeString(endata)

    dedata, err := pri.Decrypt(rand.Reader, en, sm2.EncrypterOpts{
        Mode: sm2.C1C2C3,
        Hash: sha256.New,
    })
    if err != nil {
        t.Fatal(err)
    }

    if bytes.Compare(msg, dedata) != 0 {
        t.Errorf("Test_EncryptSha256_C1C2C3_Check Decrypt error: got %s, want %s", string(dedata), string(msg))
    }
}

func Test_SignFunc(t *testing.T) {
    priv, err := sm2.GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    msg := []byte("test-passstest-passstest-passstest-passstest-passstest-passstest-passstest-passs")

    t.Run("ASN1", func(t *testing.T) {
        signed, err := sm2.Sign(rand.Reader, priv, msg, nil)
        if err != nil {
            t.Error(err)
        }

        if !sm2.Verify(pub, msg, signed, nil) {
            t.Error("veri error")
        }
    })

    t.Run("Bytes", func(t *testing.T) {
        signed, err := sm2.SignBytes(rand.Reader, priv, msg, nil)
        if err != nil {
            t.Error(err)
        }

        if !sm2.VerifyBytes(pub, msg, signed, nil) {
            t.Error("veri error")
        }
    })
}

func Test_SignLegacy(t *testing.T) {
    priv, err := sm2.GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    msg := []byte("test-passstest-passstest-passstest-passstest-passstest-passstest-passstest-passs")
    hash := sha1.Sum(msg)

    r, s, err := sm2.SignLegacy(rand.Reader, priv, hash[:])
    if err != nil {
        t.Error(err)
    }

    if !sm2.VerifyLegacy(pub, hash[:], r, s) {
        t.Error("veri error")
    }
}

func test_Encrypt_Encoding(t *testing.T, opts sm2.EncrypterOpts) {
    blockPri := decodePEM(testPrikey)
    pri, err := sm2.ParsePrivateKey(blockPri.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    blockPub := decodePEM(testPubkey)
    pub, err := sm2.ParsePublicKey(blockPub.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    plainText := "sm2-data"

    ciphertext, err := pub.Encrypt(rand.Reader, []byte(plainText), opts)
    if err != nil {
        t.Fatalf("encrypt failed %v", err)
    }

    plaintext, err := pri.Decrypt(rand.Reader, ciphertext, opts)
    if err != nil {
        t.Fatalf("decrypt failed %v", err)
    }

    if !reflect.DeepEqual(string(plaintext), plainText) {
        t.Errorf("Decrypt() = %v, want %v", string(plaintext), plainText)
    }
}

func test_EncryptASN1_Encoding(t *testing.T, opts sm2.EncrypterOpts) {
    blockPri := decodePEM(testPrikey)
    pri, err := sm2.ParsePrivateKey(blockPri.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    blockPub := decodePEM(testPubkey)
    pub, err := sm2.ParsePublicKey(blockPub.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    plainText := "sm2-data"

    ciphertext, err := pub.EncryptASN1(rand.Reader, []byte(plainText), opts)
    if err != nil {
        t.Fatalf("encrypt failed %v", err)
    }

    plaintext, err := pri.DecryptASN1(ciphertext, opts)
    if err != nil {
        t.Fatalf("decrypt failed %v", err)
    }

    if !reflect.DeepEqual(string(plaintext), plainText) {
        t.Errorf("Decrypt() = %v, want %v", string(plaintext), plainText)
    }
}

func Test_Encrypt_Encoding(t *testing.T) {
    t.Run("EncodingASN1", func(t *testing.T) {
        test_Encrypt_Encoding(t, sm2.EncrypterOpts{
            Mode:     sm2.C1C3C2,
            Hash:     sm3.New,
            Encoding: sm2.EncodingASN1,
        })
    })
    t.Run("EncodingASN1 C1C2C3", func(t *testing.T) {
        test_Encrypt_Encoding(t, sm2.EncrypterOpts{
            Mode:     sm2.C1C2C3,
            Hash:     sm3.New,
            Encoding: sm2.EncodingASN1,
        })
    })

    t.Run("EncodingBytes", func(t *testing.T) {
        test_Encrypt_Encoding(t, sm2.EncrypterOpts{
            Mode:     sm2.C1C3C2,
            Hash:     sm3.New,
            Encoding: sm2.EncodingBytes,
        })
    })
    t.Run("EncodingBytes C1C2C3", func(t *testing.T) {
        test_Encrypt_Encoding(t, sm2.EncrypterOpts{
            Mode:     sm2.C1C2C3,
            Hash:     sm3.New,
            Encoding: sm2.EncodingBytes,
        })
    })

    t.Run("EncodingASN1_2", func(t *testing.T) {
        test_EncryptASN1_Encoding(t, sm2.EncrypterOpts{
            Mode: sm2.C1C3C2,
            Hash: sm3.New,
        })
    })
    t.Run("EncodingASN1_2 C1C2C3", func(t *testing.T) {
        test_EncryptASN1_Encoding(t, sm2.EncrypterOpts{
            Mode: sm2.C1C2C3,
            Hash: sm3.New,
        })
    })

}

func test_Encrypt_Func_Encoding(t *testing.T, opts sm2.EncrypterOpts) {
    blockPri := decodePEM(testPrikey)
    pri, err := sm2.ParsePrivateKey(blockPri.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    blockPub := decodePEM(testPubkey)
    pub, err := sm2.ParsePublicKey(blockPub.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    plainText := "sm2-data"

    ciphertext, err := sm2.Encrypt(rand.Reader, pub, []byte(plainText), opts)
    if err != nil {
        t.Fatalf("encrypt failed %v", err)
    }

    plaintext, err := sm2.Decrypt(pri, ciphertext, opts)
    if err != nil {
        t.Fatalf("decrypt failed %v", err)
    }

    if !reflect.DeepEqual(string(plaintext), plainText) {
        t.Errorf("Decrypt() = %v, want %v", string(plaintext), plainText)
    }
}

func test_EncryptASN1_Func_Encoding(t *testing.T, opts sm2.EncrypterOpts) {
    blockPri := decodePEM(testPrikey)
    pri, err := sm2.ParsePrivateKey(blockPri.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    blockPub := decodePEM(testPubkey)
    pub, err := sm2.ParsePublicKey(blockPub.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    plainText := "sm2-data"

    ciphertext, err := sm2.EncryptASN1(rand.Reader, pub, []byte(plainText), opts)
    if err != nil {
        t.Fatalf("encrypt failed %v", err)
    }

    plaintext, err := sm2.DecryptASN1(pri, ciphertext, opts)
    if err != nil {
        t.Fatalf("decrypt failed %v", err)
    }

    if !reflect.DeepEqual(string(plaintext), plainText) {
        t.Errorf("Decrypt() = %v, want %v", string(plaintext), plainText)
    }
}

func Test_Encrypt_Func_Encoding(t *testing.T) {
    t.Run("EncodingASN1", func(t *testing.T) {
        test_Encrypt_Func_Encoding(t, sm2.EncrypterOpts{
            Mode:     sm2.C1C3C2,
            Hash:     sm3.New,
            Encoding: sm2.EncodingASN1,
        })
    })
    t.Run("EncodingASN1 C1C2C3", func(t *testing.T) {
        test_Encrypt_Func_Encoding(t, sm2.EncrypterOpts{
            Mode:     sm2.C1C2C3,
            Hash:     sm3.New,
            Encoding: sm2.EncodingASN1,
        })
    })

    t.Run("EncodingBytes", func(t *testing.T) {
        test_Encrypt_Func_Encoding(t, sm2.EncrypterOpts{
            Mode:     sm2.C1C3C2,
            Hash:     sm3.New,
            Encoding: sm2.EncodingBytes,
        })
    })
    t.Run("EncodingBytes C1C2C3", func(t *testing.T) {
        test_Encrypt_Func_Encoding(t, sm2.EncrypterOpts{
            Mode:     sm2.C1C2C3,
            Hash:     sm3.New,
            Encoding: sm2.EncodingBytes,
        })
    })

    t.Run("EncodingASN1_2", func(t *testing.T) {
        test_EncryptASN1_Func_Encoding(t, sm2.EncrypterOpts{
            Mode: sm2.C1C3C2,
            Hash: sm3.New,
        })
    })
    t.Run("EncodingASN1_2 C1C2C3", func(t *testing.T) {
        test_EncryptASN1_Func_Encoding(t, sm2.EncrypterOpts{
            Mode: sm2.C1C2C3,
            Hash: sm3.New,
        })
    })

}

// ============

var usedUID = []byte{
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
}

func test_Sign_Encoding(t *testing.T, opts sm2.SignerOpts) {
    priv, err := sm2.GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    msg := []byte("test-passstest-passstest-passstest-passstest-passstest-passstest-passstest-passs")

    signed, err := priv.Sign(rand.Reader, msg, opts)
    if err != nil {
        t.Error(err)
    }

    veri := pub.Verify(msg, signed, opts)
    if !veri {
        t.Error("veri error")
    }
}

func Test_Sign_Encoding(t *testing.T) {
    t.Run("EncodingASN1", func(t *testing.T) {
        test_Sign_Encoding(t, sm2.SignerOpts{
            Uid:      usedUID,
            Hash:     sm3.New,
            Encoding: sm2.EncodingASN1,
        })
    })

    t.Run("EncodingBytes", func(t *testing.T) {
        test_Sign_Encoding(t, sm2.SignerOpts{
            Uid:      usedUID,
            Hash:     sm3.New,
            Encoding: sm2.EncodingBytes,
        })
    })
}

func test_Sign_Func_Encoding(t *testing.T, opts sm2.SignerOpts) {
    priv, err := sm2.GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    msg := []byte("test-passstest-passstest-passstest-passstest-passstest-passstest-passstest-passs")

    signed, err := sm2.Sign(rand.Reader, priv, msg, opts)
    if err != nil {
        t.Error(err)
    }

    ok := sm2.Verify(pub, msg, signed, opts)
    if !ok {
        t.Error("veri error")
    }
}

func Test_Sign_Func_Encoding(t *testing.T) {
    t.Run("EncodingASN1", func(t *testing.T) {
        test_Sign_Func_Encoding(t, sm2.SignerOpts{
            Uid:      usedUID,
            Hash:     sm3.New,
            Encoding: sm2.EncodingASN1,
        })
    })

    t.Run("EncodingBytes", func(t *testing.T) {
        test_Sign_Func_Encoding(t, sm2.SignerOpts{
            Uid:      usedUID,
            Hash:     sm3.New,
            Encoding: sm2.EncodingBytes,
        })
    })
}

func Test_CheckPrivKey(t *testing.T) {
    pri := "00377febf6f6fd530121d471ec27db463c63df6a38c94a75618a57ee48824fa0"

    _, err := sm2.NewPrivateKey(fromHex(pri))
    if err != nil {
        t.Fatal(err)
    }

}
