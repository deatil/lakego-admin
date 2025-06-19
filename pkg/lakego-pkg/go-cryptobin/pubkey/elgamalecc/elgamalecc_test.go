package elgamalecc

import (
    "bytes"
    "testing"
    "math/big"
    "crypto/rand"
    "crypto/elliptic"
    "encoding/hex"
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/elliptic/secp256k1"
    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

func Test_Encrypt(t *testing.T) {
    c := elliptic.P256()

    priv, err := GenerateKey(rand.Reader, c)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    data := []byte("test-data test-data test-data test-data test-data")

    C1x, C1y, C2, err := Encrypt(rand.Reader, pub, data)
    if err != nil {
        t.Fatal(err)
    }

    p, _ := Decrypt(priv, C1x, C1y, C2)
    if !bytes.Equal(data, p) {
        t.Errorf("Test_Encrypt fail, got %x, want %x", p, data)
    }

}

func Test_Encrypt_Check(t *testing.T) {
    c := elliptic.P256()

    x := fromHex("67e87b98e8a4383098fedb448c1f3d278bebba50525dec57c0576c605bfffdda")
    Y := fromHex("045ec79d828a77af85aa9c8ef3ba5afd7674376d6b134d14b10bb4afb7fd0952b0e894f696b38096ff547bbd0a0f1d14a195f2fc9ce951901fe2925560f29d98c0")

    priv, err := NewPrivateKey(c, x)
    if err != nil {
        t.Fatal(err)
    }

    pub, err := NewPublicKey(c, Y)
    if err != nil {
        t.Fatal(err)
    }

    priv2, err := NewPrivateKey(c, x)
    if err != nil {
        t.Fatal(err)
    }

    privToPub := priv.Public()
    if !pub.Equal(privToPub) {
        t.Errorf("Test_Encrypt_Check privToPub fail")
    }

    if !priv2.Equal(priv) {
        t.Errorf("Test_Encrypt_Check priv Equal priv2 fail")
    }

    x2 := fromHex("6fbfc7f9710928bfde9398f5dab8b2a48401863a705e054d344b8db06e043373")
    Y2 := fromHex("0476e321b586be3cb474bd7f849a6bb17354d6346de312aa44ce646911132d3743117354253159f61cdfeaf896cbf3b6070334a003b49a18934838b3bfff98cf77")

    priv3, err := NewPrivateKey(c, x2)
    if err != nil {
        t.Fatal(err)
    }

    pub3, err := NewPublicKey(c, Y2)
    if err != nil {
        t.Fatal(err)
    }

    if priv3.Equal(priv) {
        t.Errorf("Test_Encrypt_Check priv3 should not Equal priv")
    }
    if pub3.Equal(pub) {
        t.Errorf("Test_Encrypt_Check pub3 should not Equal pub")
    }

    data := []byte("Hello")

    C1x, C1y, C2, err := Encrypt(rand.Reader, pub, data)
    if err != nil {
        t.Fatal(err)
    }

    // C1Bytes := elliptic.Marshal(pub.Curve, C1x, C1y)
    // C1=04af7035184190ce72b1ee000ec8f18927a664c23358ce4d41ff757283a5846bb58c19c551753ea0af151c31c1a3698606af565c122a387dbe67d7fa5deba2393f
    // t.Errorf("C1Bytes: %x", C2)

    p, _ := Decrypt(priv, C1x, C1y, C2)
    if !bytes.Equal(data, p) {
        t.Errorf("ElgamalDecrypt fail, got %x, want %x", p, data)
    }

    C1 := fromHex("04af7035184190ce72b1ee000ec8f18927a664c23358ce4d41ff757283a5846bb58c19c551753ea0af151c31c1a3698606af565c122a387dbe67d7fa5deba2393f")
    C22, _ := new(big.Int).SetString("64998866770800537035816591092081487793369751526287129670052291837083837454710935744289325621649282383337514803150244272041445838052262073601284819093853352", 10)

    C1x2, C1y2 := elliptic.Unmarshal(priv.Curve, C1)
    p2, _ := Decrypt(priv, C1x2, C1y2, C22)
    if !bytes.Equal(data, p2) {
        t.Errorf("Test_Encrypt_Check fail, got %x, want %x", p2, data)
    }
}

func Test_EncryptASN1(t *testing.T) {
    c := elliptic.P256()

    priv, err := GenerateKey(rand.Reader, c)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    data := []byte("test-data test-data test-data test-data test-data")

    ct, err := EncryptASN1(rand.Reader, pub, data)
    if err != nil {
        t.Fatal(err)
    }

    p, _ := DecryptASN1(priv, ct)
    if !bytes.Equal(data, p) {
        t.Errorf("Test_Encrypt fail, got %x, want %x", p, data)
    }

}

func Test_EncryptASN1_Check(t *testing.T) {
    c := elliptic.P256()

    x := fromHex("67e87b98e8a4383098fedb448c1f3d278bebba50525dec57c0576c605bfffdda")
    Y := fromHex("045ec79d828a77af85aa9c8ef3ba5afd7674376d6b134d14b10bb4afb7fd0952b0e894f696b38096ff547bbd0a0f1d14a195f2fc9ce951901fe2925560f29d98c0")

    priv, err := NewPrivateKey(c, x)
    if err != nil {
        t.Fatal(err)
    }

    pub, err := NewPublicKey(c, Y)
    if err != nil {
        t.Fatal(err)
    }

    data := []byte("Hello")

    ct, err := EncryptASN1(rand.Reader, pub, data)
    if err != nil {
        t.Fatal(err)
    }

    p, _ := DecryptASN1(priv, ct)
    if !bytes.Equal(data, p) {
        t.Errorf("ElgamalDecrypt fail, got %x, want %x", p, data)
    }

    C1 := fromHex("04af7035184190ce72b1ee000ec8f18927a664c23358ce4d41ff757283a5846bb58c19c551753ea0af151c31c1a3698606af565c122a387dbe67d7fa5deba2393f")
    C2, _ := new(big.Int).SetString("64998866770800537035816591092081487793369751526287129670052291837083837454710935744289325621649282383337514803150244272041445838052262073601284819093853352", 10)

    enc, err := asn1.Marshal(encryptedData{
        C1: C1,
        C2: C2,
    })

    p2, _ := DecryptASN1(priv, enc)
    if !bytes.Equal(data, p2) {
        t.Errorf("Test_Encrypt_Check fail, got %x, want %x", p2, data)
    }
}

func Test_EncryptASN1_Check2(t *testing.T) {
    c := secp256k1.S256()

    x := fromHex("58202239faae18806aa03e7b8cc287a2c213081c3f3631aaea63ce83077b7e6c")
    Y := fromHex("0408ced9c22629139d373b23209bc95d6be34ef13a8cc5c1a7504ea988bfe04702f3278908d94eb3e6b5091701e4f2f30d3494b7010afeec96c069215d8aef27f6")

    priv, err := NewPrivateKey(c, x)
    if err != nil {
        t.Fatal(err)
    }

    pub, err := NewPublicKey(c, Y)
    if err != nil {
        t.Fatal(err)
    }

    data := []byte("00Hello")

    ct, err := EncryptASN1(rand.Reader, pub, data)
    if err != nil {
        t.Fatal(err)
    }

    p, _ := DecryptASN1(priv, ct)
    if !bytes.Equal(data, p) {
        t.Errorf("ElgamalDecrypt fail, got %x, want %x", p, data)
    }

    C1 := fromHex("04c82264c17f181e469a1cb258b2c48300f692a65e93181a32fe8c2d43a2d3d7e9892599a2a538a64726ac12bf78f5e08b0e77ccd4fe4bf2a902e831e181f900ff")
    C2, _ := new(big.Int).SetString("60465485415873670516518360642899670456852166251606531814121725105989579773216426234104724728428181230636039521187393414737061049499825803369974263911235347", 10)

    enc, err := asn1.Marshal(encryptedData{
        C1: C1,
        C2: C2,
    })

    p2, _ := DecryptASN1(priv, enc)
    if !bytes.Equal(data, p2) {
        t.Errorf("Test_EncryptASN1_Check2 fail, got %x, want %x", p2, data)
    }
}

func Test_EncryptASN1_Check3(t *testing.T) {
    c := secp256k1.S256()

    x := fromHex("f64d526828db07a022cd6b015c0e98cadc2ebc972fa3b89c247b0542f277e7b7")
    Y := fromHex("04f12647c9bd5d3bf8c8169da4e32633912f8220c2eff81a9114ffb6ce8045dad0b947c83e5d57eff38af3e9f99ed40072280bac4ef14a030defca3d8e478ac910")

    priv, err := NewPrivateKey(c, x)
    if err != nil {
        t.Fatal(err)
    }

    pub, err := NewPublicKey(c, Y)
    if err != nil {
        t.Fatal(err)
    }

    data := []byte("Hello")

    ct, err := EncryptASN1(rand.Reader, pub, data)
    if err != nil {
        t.Fatal(err)
    }

    p, _ := DecryptASN1(priv, ct)
    if !bytes.Equal(data, p) {
        t.Errorf("ElgamalDecrypt fail, got %x, want %x", p, data)
    }

    C1 := fromHex("04dda83f84e290ee6183c99eac3ddf46a31b74b8c7bf0011688ac67afb53479384118539fab5649fb4356f8a5de6377d864985ad87399b4cd97317fc541bac3c6f")
    C2, _ := new(big.Int).SetString("61738521896366194598781997268525606632833970892953952697258628550069003116299643941844766144610099424143434787628598037087667609225907007597296768147814038", 10)

    enc, err := asn1.Marshal(encryptedData{
        C1: C1,
        C2: C2,
    })

    p2, _ := DecryptASN1(priv, enc)
    if !bytes.Equal(data, p2) {
        t.Errorf("Test_EncryptASN1_Check3 fail, got %x, want %x", p2, data)
    }
}

func Test_key(t *testing.T) {
    test_key(t, elliptic.P224())
    test_key(t, elliptic.P256())
    test_key(t, elliptic.P384())
    test_key(t, elliptic.P521())

    test_key(t, secp256k1.S256())
}

func test_key(t *testing.T, c elliptic.Curve) {
    priv, err := GenerateKey(rand.Reader, c)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    {
        priKey, err := MarshalECPrivateKey(priv)
        if err != nil {
            t.Fatal(err)
        }

        parsekey, err := ParseECPrivateKey(priKey)
        if err != nil {
            t.Fatal(err)
        }

        if !parsekey.Equal(priv) {
            t.Error("MarshalECPrivateKey fail")
        }

    }

    {
        priKey, err := MarshalPrivateKey(priv)
        if err != nil {
            t.Fatal(err)
        }

        parsekey, err := ParsePrivateKey(priKey)
        if err != nil {
            t.Fatal(err)
        }

        if !parsekey.Equal(priv) {
            t.Error("MarshalPrivateKey fail")
        }

    }

    {
        pubKey, err := MarshalPublicKey(pub)
        if err != nil {
            t.Fatal(err)
        }

        parsekey, err := ParsePublicKey(pubKey)
        if err != nil {
            t.Fatal(err)
        }

        if !parsekey.Equal(pub) {
            t.Error("MarshalPublicKey fail")
        }

    }

}

func Test_PrivateKeyDecrypt_Check(t *testing.T) {
    c := elliptic.P256()

    x := fromHex("67e87b98e8a4383098fedb448c1f3d278bebba50525dec57c0576c605bfffdda")

    priv, err := NewPrivateKey(c, x)
    if err != nil {
        t.Fatal(err)
    }

    data := []byte("Hello")

    C1 := fromHex("04af7035184190ce72b1ee000ec8f18927a664c23358ce4d41ff757283a5846bb58c19c551753ea0af151c31c1a3698606af565c122a387dbe67d7fa5deba2393f")
    C2, _ := new(big.Int).SetString("64998866770800537035816591092081487793369751526287129670052291837083837454710935744289325621649282383337514803150244272041445838052262073601284819093853352", 10)

    enc, err := asn1.Marshal(encryptedData{
        C1: C1,
        C2: C2,
    })

    p2, _ := priv.Decrypt(nil, enc, nil)
    if !bytes.Equal(data, p2) {
        t.Errorf("Test_PrivateKeyDecrypt_Check fail, got %x, want %x", p2, data)
    }
}

func Test_NewPrivateKey(t *testing.T) {
    c := elliptic.P256()

    priv, err := GenerateKey(rand.Reader, c)
    if err != nil {
        t.Fatal(err)
    }
    pub := &priv.PublicKey

    priv2, err := GenerateKey(rand.Reader, c)
    if err != nil {
        t.Fatal(err)
    }
    pub2 := &priv2.PublicKey

    privBytes := PrivateKeyTo(priv)
    pubBytes := PublicKeyTo(pub)

    newPriv, err := NewPrivateKey(c, privBytes)
    if err != nil {
        t.Fatal(err)
    }
    newPub, err := NewPublicKey(c, pubBytes)
    if err != nil {
        t.Fatal(err)
    }

    cryptobin_test.Equal(t, priv, newPriv, "NewPrivateKey 1")
    cryptobin_test.Equal(t, pub, newPub, "NewPublicKey 1")

    cryptobin_test.NotEqual(t, priv2, newPriv, "NewPrivateKey 1")
    cryptobin_test.NotEqual(t, pub2, newPub, "NewPublicKey 1")
}
