package gost

import (
    "io"
    "bytes"
    "math/big"
    "crypto"
    "crypto/rand"
    "testing"
    "encoding/hex"
    "crypto/elliptic"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func encodeHex(src []byte) string {
    return hex.EncodeToString(src)
}

func decodeHex(s string) []byte {
    res, _ := hex.DecodeString(s)
    return res
}

func decodeDec(s string) *big.Int {
    res, _ := new(big.Int).SetString(s, 10)
    return res
}

func Test_CurveInterface(t *testing.T) {
    c := CurveIdGostR34102001TestParamSet()

    var _ elliptic.Curve = c
}

func Test_SignerInterface(t *testing.T) {
    c := CurveIdGostR34102001TestParamSet()

    priv, err := GenerateKey(rand.Reader, c)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    var _ crypto.Signer = priv
    var _ crypto.PublicKey = pub
}

func Test_NewPrivateKey(t *testing.T) {
    c := CurveIdGostR34102001TestParamSet()

    priv, err := GenerateKey(rand.Reader, c)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    priBytes := PrivateKeyTo(priv)
    if len(priBytes) == 0 {
        t.Error("fail PrivateKeyTo")
    }
    pubBytes := PublicKeyTo(pub)
    if len(pubBytes) == 0 {
        t.Error("fail PublicKeyTo")
    }

    priv2, err := NewPrivateKey(c, priBytes)
    if err != nil {
        t.Fatal(err)
    }
    pub2, err := NewPublicKey(c, pubBytes)
    if err != nil {
        t.Fatal(err)
    }

    if !priv2.Equal(priv) {
        t.Error("NewPrivateKey make fail")
    }

    if !pub2.Equal(pub) {
        t.Error("NewPublicKey make fail")
    }
}

func Test_Sign(t *testing.T) {
    message := make([]byte, 32)
    _, err := io.ReadFull(rand.Reader, message)
    if err != nil {
        t.Fatal(err)
    }

    priv, err := GenerateKey(rand.Reader, CurveIdGostR34102001TestParamSet())
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    signed, err := priv.Sign(rand.Reader, message, nil)
    if err != nil {
        t.Fatal(err)
    }

    valid, err := pub.Verify(message, signed)
    if err != nil {
        t.Fatal(err)
    }

    if !valid {
        t.Error("Verify: valid error")
    }
}

func Test_SignASN1(t *testing.T) {
    message := make([]byte, 32)
    _, err := io.ReadFull(rand.Reader, message)
    if err != nil {
        t.Fatal(err)
    }

    priv, err := GenerateKey(rand.Reader, CurveIdGostR34102001TestParamSet())
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    signed, err := priv.SignASN1(rand.Reader, message, nil)
    if err != nil {
        t.Fatal(err)
    }

    valid, err := pub.VerifyASN1(message, signed)
    if err != nil {
        t.Fatal(err)
    }

    if !valid {
        t.Error("VerifyASN1: valid error")
    }
}

func Test_SignToRS_Msg_check(t *testing.T) {
    eq := cryptobin_test.AssertEqualT(t)

    message := make([]byte, 32)
    _, err := io.ReadFull(rand.Reader, message)
    if err != nil {
        t.Fatal(err)
    }

    newMessage := make([]byte, 32)
    copy(newMessage, message)

    priv, err := GenerateKey(rand.Reader, CurveIdGostR34102001TestParamSet())
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    r, s, err := SignToRS(rand.Reader, priv, message)
    if err != nil {
        t.Fatal(err)
    }

    eq(message, newMessage, "Test_SignToRS_Msg_check-SignToRS")

    valid, err := VerifyWithRS(pub, message, r, s)
    if err != nil {
        t.Fatal(err)
    }

    eq(message, newMessage, "Test_SignToRS_Msg_check-VerifyWithRS")

    if !valid {
        t.Error("VerifyWithRS: valid error")
    }
}

func Test_Sign_Func(t *testing.T) {
    message := make([]byte, 32)
    _, err := io.ReadFull(rand.Reader, message)
    if err != nil {
        t.Fatal(err)
    }

    priv, err := GenerateKey(rand.Reader, CurveIdGostR34102001TestParamSet())
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    signed, err := Sign(rand.Reader, priv, message)
    if err != nil {
        t.Fatal(err)
    }

    valid, err := Verify(pub, message, signed)
    if err != nil {
        t.Fatal(err)
    }

    if !valid {
        t.Error("Verify: valid error")
    }
}

func Test_SignASN1_Func(t *testing.T) {
    message := make([]byte, 32)
    _, err := io.ReadFull(rand.Reader, message)
    if err != nil {
        t.Fatal(err)
    }

    priv, err := GenerateKey(rand.Reader, CurveIdGostR34102001TestParamSet())
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    signed, err := SignASN1(rand.Reader, priv, message)
    if err != nil {
        t.Fatal(err)
    }

    valid, err := VerifyASN1(pub, message, signed)
    if err != nil {
        t.Fatal(err)
    }

    if !valid {
        t.Error("VerifyASN1: valid error")
    }
}

func Test_MarshalPublicKey(t *testing.T) {
    priv, err := GenerateKey(rand.Reader, CurveIdGostR34102001TestParamSet())
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    pubkey := PublicKeyTo(pub)

    newPub, err := NewPublicKey(pub.Curve, pubkey)
    if err != nil {
        t.Fatal(err)
    }

    if !newPub.Equal(pub) {
        t.Error("PublicKey Equal error")
    }
}

func Test_MarshalPrivateKey(t *testing.T) {
    priv, err := GenerateKey(rand.Reader, CurveIdGostR34102001TestParamSet())
    if err != nil {
        t.Fatal(err)
    }

    privkey := PrivateKeyTo(priv)

    newPriv, err := NewPrivateKey(priv.Curve, privkey)
    if err != nil {
        t.Fatal(err)
    }

    if !newPriv.Equal(priv) {
        t.Error("PrivateKey Equal error")
    }
}

func Test_341001(t *testing.T) {
    eq := cryptobin_test.AssertEqualT(t)
    ifbool := cryptobin_test.AssertBoolT(t)

    prv := []byte{
        0x7A, 0x92, 0x9A, 0xDE, 0x78, 0x9B, 0xB9, 0xBE,
        0x10, 0xED, 0x35, 0x9D, 0xD3, 0x9A, 0x72, 0xC1,
        0x1B, 0x60, 0x96, 0x1F, 0x49, 0x39, 0x7E, 0xEE,
        0x1D, 0x19, 0xCE, 0x98, 0x91, 0xEC, 0x3B, 0x28,
    }
    pub_x := []byte{
        0x7F, 0x2B, 0x49, 0xE2, 0x70, 0xDB, 0x6D, 0x90,
        0xD8, 0x59, 0x5B, 0xEC, 0x45, 0x8B, 0x50, 0xC5,
        0x85, 0x85, 0xBA, 0x1D, 0x4E, 0x9B, 0x78, 0x8F,
        0x66, 0x89, 0xDB, 0xD8, 0xE5, 0x6F, 0xD8, 0x0B,
    }
    pub_y := []byte{
        0x26, 0xF1, 0xB4, 0x89, 0xD6, 0x70, 0x1D, 0xD1,
        0x85, 0xC8, 0x41, 0x3A, 0x97, 0x7B, 0x3C, 0xBB,
        0xAF, 0x64, 0xD1, 0xC5, 0x93, 0xD2, 0x66, 0x27,
        0xDF, 0xFB, 0x10, 0x1A, 0x87, 0xFF, 0x77, 0xDA,
    }
    digest := []byte{
        0x2D, 0xFB, 0xC1, 0xB3, 0x72, 0xD8, 0x9A, 0x11,
        0x88, 0xC0, 0x9C, 0x52, 0xE0, 0xEE, 0xC6, 0x1F,
        0xCE, 0x52, 0x03, 0x2A, 0xB1, 0x02, 0x2E, 0x8E,
        0x67, 0xEC, 0xE6, 0x67, 0x2B, 0x04, 0x3E, 0xE5,
    }
    signature := []byte{
        0x41, 0xAA, 0x28, 0xD2, 0xF1, 0xAB, 0x14, 0x82,
        0x80, 0xCD, 0x9E, 0xD5, 0x6F, 0xED, 0xA4, 0x19,
        0x74, 0x05, 0x35, 0x54, 0xA4, 0x27, 0x67, 0xB8,
        0x3A, 0xD0, 0x43, 0xFD, 0x39, 0xDC, 0x04, 0x93,
        0x01, 0x45, 0x6C, 0x64, 0xBA, 0x46, 0x42, 0xA1,
        0x65, 0x3C, 0x23, 0x5A, 0x98, 0xA6, 0x02, 0x49,
        0xBC, 0xD6, 0xD3, 0xF7, 0x46, 0xB6, 0x31, 0xDF,
        0x92, 0x80, 0x14, 0xF6, 0xC5, 0xBF, 0x9C, 0x40,
    }

    signature = append(signature[32:], signature[:32]...)
    c := CurveIdGostR34102001TestParamSet()

    prikey, err := NewPrivateKey(c, Reverse(prv))
    if err != nil {
        t.Fatal(err)
    }

    pub := &prikey.PublicKey

    eq(prikey.X.Bytes(), pub_x, "Test_341001-pub_x")
    eq(prikey.Y.Bytes(), pub_y, "Test_341001-pub_y")

    s, err := Sign(rand.Reader, prikey, digest)
    if err != nil {
        t.Fatal(err)
    }

    veri, _ := Verify(pub, digest, s)
    ifbool(veri, "Test_341001-Verify-1")

    veri2, _ := Verify(pub, Reverse(digest), signature)
    ifbool(veri2, "Test_341001-Verify-2")

}

func Test_34102012(t *testing.T) {
    eq := cryptobin_test.AssertEqualT(t)

    curve := CurveIdGostR34102001TestParamSet()

    pri := decodeHex("7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28")

    prikey, err := NewPrivateKey(curve, Reverse(pri))
    if err != nil {
        t.Fatal(err)
    }

    digest := decodeHex("2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5")
    rand := decodeHex("77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3")

    signature, err := Sign(bytes.NewBuffer(rand), prikey, Reverse(digest))
    if err != nil {
        t.Fatal(err)
    }

    r := "41aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc0493"
    s := "01456c64ba4642a1653c235a98a60249bcd6d3f746b631df928014f6c5bf9c40"

    eq(encodeHex(signature), s + r, "Test_34102012")

}

func Test_34102012_2(t *testing.T) {
    eq := cryptobin_test.AssertEqualT(t)

    curve, err := NewCurve(
        decodeDec("3623986102229003635907788753683874306021320925534678605086546150450856166624002482588482022271496854025090823603058735163734263822371964987228582907372403"),
        decodeDec("3623986102229003635907788753683874306021320925534678605086546150450856166623969164898305032863068499961404079437936585455865192212970734808812618120619743"),
        big.NewInt(7),
        decodeDec("1518655069210828534508950034714043154928747527740206436194018823352809982443793732829756914785974674866041605397883677596626326413990136959047435811826396"),
        decodeDec("1928356944067022849399309401243137598997786635459507974357075491307766592685835441065557681003184874819658004903212332884252335830250729527632383493573274"),
        decodeDec("2288728693371972859970012155529478416353562327329506180314497425931102860301572814141997072271708807066593850650334152381857347798885864807605098724013854"),
        nil,
        nil,
        nil,
    )
    if err != nil {
        t.Fatal(err)
    }

    pri := decodeHex("0BA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508B102072E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4")

    prikey, err := NewPrivateKey(curve, Reverse(pri))
    if err != nil {
        t.Fatal(err)
    }

    digest := decodeHex("3754F3CFACC9E0615C4F4A7C4D8DAB531B09B6F9C170C533A71D147035B0C5917184EE536593F4414339976C647C5D5A407ADEDB1D560C4FC6777D2972075B8C")
    rand := decodeHex("0359E7F4B1410FEACC570456C6801496946312120B39D019D455986E364F365886748ED7A44B3E794434006011842286212273A6D14CF70EA3AF71BB1AE679F1")

    signature, err := Sign(bytes.NewBuffer(rand), prikey, Reverse(digest))
    if err != nil {
        t.Fatal(err)
    }

    r := "2f86fa60a081091a23dd795e1e3c689ee512a3c82ee0dcc2643c78eea8fcacd35492558486b20f1c9ec197c90699850260c93bcbcd9c5c3317e19344e173ae36"
    s := "1081b394696ffe8e6585e7a9362d26b6325f56778aadbc081c0bfbe933d52ff5823ce288e8c4f362526080df7f70ce406a6eeb1f56919cb92a9853bde73e5b4a"

    eq(encodeHex(signature), s + r, "Test_34102012")

}

func Test_UVXYConversion(t *testing.T) {
    eq := cryptobin_test.AssertEqualT(t)

    t.Run("test curve1", func(t *testing.T) {
        c := CurveIdtc26gost34102012256paramSetA()

        u := bigIntFromBytes([]byte{0x0D})
        v := bigIntFromBytes(decodeHex("60CA1E32AA475B348488C38FAB07649CE7EF8DBE87F22E81F92B2592DBA300E7"))

        x, y := UV2XY(c, u, v)
        eq([]*big.Int{x, y}, []*big.Int{c.X, c.Y}, "UV2XY")

        x2, y2 := XY2UV(c, c.X, c.Y)
        eq([]*big.Int{x2, y2}, []*big.Int{u, v}, "XY2UV")
    })

    t.Run("test curve2", func(t *testing.T) {
        c := CurveIdtc26gost34102012512paramSetC()

        u := bigIntFromBytes([]byte{0x12})
        v := bigIntFromBytes(decodeHex("469AF79D1FB1F5E16B99592B77A01E2A0FDFB0D01794368D9A56117F7B38669522DD4B650CF789EEBF068C5D139732F0905622C04B2BAAE7600303EE73001A3D"))

        x, y := UV2XY(c, u, v)
        eq([]*big.Int{x, y}, []*big.Int{c.X, c.Y}, "UV2XY")

        x2, y2 := XY2UV(c, c.X, c.Y)
        eq([]*big.Int{x2, y2}, []*big.Int{u, v}, "XY2UV")
    })
}

func Test_NamedCurveFromName(t *testing.T) {
    eq := cryptobin_test.AssertEqualT(t)

    tests := []string{
        // "GostR34102001ParamSetcc",
        "id-GostR3410-2001-TestParamSet",
        // "id-tc26-gost-3410-12-256-paramSetA",
        // "id-tc26-gost-3410-12-256-paramSetB",
        // "id-tc26-gost-3410-12-256-paramSetC",
        // "id-tc26-gost-3410-12-256-paramSetD",
        // "id-tc26-gost-3410-12-512-paramSetTest",
        // "id-tc26-gost-3410-12-512-paramSetA",
        // "id-tc26-gost-3410-12-512-paramSetB",
        // "id-tc26-gost-3410-12-512-paramSetC",
        "id-GostR3410-2001-CryptoPro-A-ParamSet",
        "id-GostR3410-2001-CryptoPro-B-ParamSet",
        "id-GostR3410-2001-CryptoPro-C-ParamSet",
        "id-GostR3410-2001-CryptoPro-XchA-ParamSet",
        "id-GostR3410-2001-CryptoPro-XchB-ParamSet",
        "id-tc26-gost-3410-2012-256-paramSetA",
        "id-tc26-gost-3410-2012-256-paramSetB",
        "id-tc26-gost-3410-2012-256-paramSetC",
        "id-tc26-gost-3410-2012-256-paramSetD",
        "id-tc26-gost-3410-2012-512-paramSetTest",
        "id-tc26-gost-3410-2012-512-paramSetA",
        "id-tc26-gost-3410-2012-512-paramSetB",
        "id-tc26-gost-3410-2012-512-paramSetC",
    }

    for _, td := range tests {
        t.Run("test " + td, func(t *testing.T) {
            curve := NamedCurveFromName(td)
            if curve != nil {
                eq(curve.Name, td, "NamedCurveFromName")
            } else {
                t.Error(td)
            }
        })
    }

}
