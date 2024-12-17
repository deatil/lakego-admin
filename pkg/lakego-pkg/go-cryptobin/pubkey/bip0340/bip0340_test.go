package bip0340

import (
    "fmt"
    "bytes"
    "crypto"
    "strings"
    "testing"
    "math/big"
    "crypto/rand"
    "crypto/sha256"
    "crypto/sha512"
    "crypto/elliptic"
    "encoding/hex"
    "encoding/pem"
    "encoding/base64"

    "github.com/deatil/go-cryptobin/elliptic/frp256v1"
    "github.com/deatil/go-cryptobin/elliptic/secp256k1"
)

func str(s string) string {
    var sb strings.Builder
    sb.Grow(len(s))
    s = strings.TrimPrefix(s, "0x")
    for _, c := range s {
        switch {
        case '0' <= c && c <= '9':
            sb.WriteRune(c)
        case 'a' <= c && c <= 'f':
            sb.WriteRune(c)
        case 'A' <= c && c <= 'F':
            sb.WriteRune(c)
        }
    }

    return sb.String()
}

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(str(s))
    return h
}

func toHex(src []byte) string {
    return hex.EncodeToString(src)
}

func fromBase64(s string) []byte {
    res, _ := base64.StdEncoding.DecodeString(s)
    return res
}

func toBigint(s string) *big.Int {
    result, _ := new(big.Int).SetString(str(s), 16)

    return result
}

func decodePEM(pubPEM string) []byte {
    block, _ := pem.Decode([]byte(pubPEM))
    if block == nil {
        panic("failed to parse PEM block containing the key")
    }

    return block.Bytes
}

func encodePEM(src []byte, typ string) string {
    keyBlock := &pem.Block{
        Type:  typ,
        Bytes: src,
    }

    keyData := pem.EncodeToMemory(keyBlock)

    return string(keyData)
}

func Test_Interface(t *testing.T) {
    var _ crypto.Signer     = (*PrivateKey)(nil)
    var _ crypto.SignerOpts = (*SignerOpts)(nil)
}

func Test_NewPrivateKey(t *testing.T) {
    p224 := elliptic.P224()

    priv, err := GenerateKey(rand.Reader, p224)
    if err != nil {
        t.Fatal(err)
    }

    privBytes := PrivateKeyTo(priv)
    priv2, err := NewPrivateKey(p224, privBytes)
    if err != nil {
        t.Fatal(err)
    }

    if !priv2.Equal(priv) {
        t.Error("NewPrivateKey Equal error")
    }

    // ======

    pub := &priv.PublicKey

    pubBytes := PublicKeyTo(pub)
    pub2, err := NewPublicKey(p224, pubBytes)
    if err != nil {
        t.Fatal(err)
    }

    if !pub2.Equal(pub) {
        t.Error("NewPublicKey Equal error")
    }
}

func Test_SignerInterface(t *testing.T) {
    priv, err := GenerateKey(rand.Reader, elliptic.P224())
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    var _ crypto.Signer = priv
    var _ crypto.PublicKey = pub
}

func Test_SignVerify(t *testing.T) {
    priv, err := GenerateKey(rand.Reader, elliptic.P224())
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    data := []byte("test-data test-data test-data test-data test-data")

    sig, err := Sign(rand.Reader, priv, sha256.New, data)
    if err != nil {
        t.Fatal(err)
    }

    res := Verify(pub, sha256.New, data, sig)
    if !res {
        t.Error("Verify fail")
    }

}

func Test_SignVerify2(t *testing.T) {
    priv, err := GenerateKey(rand.Reader, elliptic.P224())
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    data := []byte("test-data test-data test-data test-data test-data")

    sig, err := priv.Sign(rand.Reader, data, &SignerOpts{
        Hash: sha256.New,
    })
    if err != nil {
        t.Fatal(err)
    }

    res, _ := pub.Verify(data, sig, &SignerOpts{
        Hash: sha256.New,
    })
    if !res {
        t.Error("Verify fail")
    }

}

func Test_SignBytes(t *testing.T) {
    t.Run("P224 sha256", func(t *testing.T) {
        test_SignBytes(t, elliptic.P224(), sha256.New)
    })
    t.Run("P256 sha256", func(t *testing.T) {
        test_SignBytes(t, elliptic.P256(), sha256.New)
    })
    t.Run("P384 sha256", func(t *testing.T) {
        test_SignBytes(t, elliptic.P384(), sha256.New)
    })
    t.Run("P384 sha384", func(t *testing.T) {
        test_SignBytes(t, elliptic.P384(), sha512.New384)
    })
    t.Run("P384 sha512", func(t *testing.T) {
        test_SignBytes(t, elliptic.P384(), sha512.New)
    })
    t.Run("P521 sha256", func(t *testing.T) {
        test_SignBytes(t, elliptic.P521(), sha256.New)
    })

    t.Run("FRP256v1 sha256", func(t *testing.T) {
        test_SignBytes(t, frp256v1.FRP256v1(), sha256.New)
    })
    t.Run("S256 sha256", func(t *testing.T) {
        test_SignBytes(t, secp256k1.S256(), sha256.New)
    })
}

func test_SignBytes(t *testing.T, c elliptic.Curve, h Hasher) {
    priv, err := GenerateKey(rand.Reader, c)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    data := []byte("test-data test-data test-data test-data test-data")

    sig, err := SignBytes(rand.Reader, priv, h, data)
    if err != nil {
        t.Fatal(err)
    }

    res := VerifyBytes(pub, h, data, sig)
    if !res {
        t.Error("Verify fail")
    }

}

func Test_bigintIsodd(t *testing.T) {
    if !bigintIsodd(big.NewInt(1)) {
        t.Error("one is odd")
    }

    if bigintIsodd(big.NewInt(2)) {
        t.Error("2 is not odd")
    }

    if !bigintIsodd(big.NewInt(3)) {
        t.Error("3 is odd")
    }

    if bigintIsodd(big.NewInt(4)) {
        t.Error("4 is not odd")
    }

    if !bigintIsodd(big.NewInt(5)) {
        t.Error("5 is odd")
    }
}

func Test_S256_Curve_Add(t *testing.T) {
    {
        a1 := toBigint("dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659")
        b1 := toBigint("2ce19b946c4ee58546f5251d441a065ea50735606985e5b228788bec4e582898")
        a2 := toBigint("dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8")
        b2 := toBigint("f594bb5f72b37faae396a4259ea64ed5e6fdeb2a51c6467582b275925fab1394")

        xx, yy := S256().Add(a1, b1, a2, b2)

        xx2 := fmt.Sprintf("%x", xx.Bytes())
        yy2 := fmt.Sprintf("%x", yy.Bytes())

        xxcheck := "0b4b8b19e1666914c37647bf3eac2acc4348b02ef8b1f2940c8bf10a381df22c"
        yycheck := "1fbbb6a4be23f0019261e05f4d26114059b001649b998160020c0c4c31000ce5"

        if xx2 != xxcheck {
            t.Errorf("xx fail, got %s, want %s", xx2, xxcheck)
        }
        if yy2 != yycheck {
            t.Errorf("yy fail, got %s, want %s", yy2, yycheck)
        }
    }

    {
        a1 := toBigint("dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659")
        b1 := toBigint("2ce19b946c4ee58546f5251d441a065ea50735606985e5b228788bec4e582898")

        xx, yy := S256().Add(a1, b1, a1, b1)

        xx2 := fmt.Sprintf("%x", xx.Bytes())
        yy2 := fmt.Sprintf("%x", yy.Bytes())

        xxcheck := "768c61d8c3acc2bbbf37dec4e62b9c481802fd817a4dbc7d5542f02375412945"
        yycheck := "e227f7076346296e92364b75508102d997f66170764bcffb2bce80ff0e77be0a"

        if xx2 != xxcheck {
            t.Errorf("xx fail, got %s, want %s", xx2, xxcheck)
        }
        if yy2 != yycheck {
            t.Errorf("yy fail, got %s, want %s", yy2, yycheck)
        }
    }

    {
        a1 := toBigint("dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659")
        b1 := toBigint("2ce19b946c4ee58546f5251d441a065ea50735606985e5b228788bec4e582898")

        xx, yy := S256().Double(a1, b1)

        xx2 := fmt.Sprintf("%x", xx.Bytes())
        yy2 := fmt.Sprintf("%x", yy.Bytes())

        xxcheck := "768c61d8c3acc2bbbf37dec4e62b9c481802fd817a4dbc7d5542f02375412945"
        yycheck := "e227f7076346296e92364b75508102d997f66170764bcffb2bce80ff0e77be0a"

        if xx2 != xxcheck {
            t.Errorf("xx fail, got %s, want %s", xx2, xxcheck)
        }
        if yy2 != yycheck {
            t.Errorf("yy fail, got %s, want %s", yy2, yycheck)
        }
    }

    {
        a1 := toBigint("dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659")
        b1 := toBigint("2ce19b946c4ee58546f5251d441a065ea50735606985e5b228788bec4e582898")

        xx, yy := secp256k1.S256().Double(a1, b1)

        xx2 := fmt.Sprintf("%x", xx.Bytes())
        yy2 := fmt.Sprintf("%x", yy.Bytes())

        xxcheck := "768c61d8c3acc2bbbf37dec4e62b9c481802fd817a4dbc7d5542f02375412945"
        yycheck := "e227f7076346296e92364b75508102d997f66170764bcffb2bce80ff0e77be0a"

        if xx2 != xxcheck {
            t.Errorf("xx fail, got %s, want %s", xx2, xxcheck)
        }
        if yy2 != yycheck {
            t.Errorf("yy fail, got %s, want %s", yy2, yycheck)
        }
    }
}

func Test_Vec_Check(t *testing.T) {
    for i, td := range testSigVec {
        t.Run(fmt.Sprintf("index %d", i), func(t *testing.T) {
            if len(td.secretKey) > 0 {
                priv, err := NewPrivateKey(S256(), td.secretKey)
                if err != nil {
                    t.Fatal(err)
                }

                pub := &priv.PublicKey

                pubBytes := pub.X.Bytes()

                // check publicKey
                if !bytes.Equal(pubBytes, td.publicKey) {
                    t.Errorf("PublicKey got: %x, want: %x", pubBytes, td.publicKey)
                }

                // do sig
                k := new(big.Int).SetBytes(td.auxRand)

                r, s, err := SignUsingKToRS(k, priv, sha256.New, td.message)
                if err != nil {
                    t.Error("SignUsingKToRS fail")
                }

                // check sig
                curveParams := S256().Params()
                p := curveParams.P

                plen := (p.BitLen() + 7) / 8
                qlen := (curveParams.BitSize + 7) / 8

                sig := make([]byte, plen + qlen)

                r.FillBytes(sig[:plen])
                s.FillBytes(sig[plen:])

                if !bytes.Equal(sig, td.signature) {
                    t.Errorf("sig fail, got: %x, want: %x", sig, td.signature)
                }

            }

            pubBytes := append([]byte{byte(3)}, td.publicKey...)

            x, y := elliptic.UnmarshalCompressed(S256(), pubBytes)
            if x == nil || y == nil {
                t.Fatal("publicKey error")
            }

            pubkey := &PublicKey{
                Curve: S256(),
                X: x,
                Y: y,
            }

            veri := VerifyBytes(pubkey, sha256.New, td.message, td.signature)
            if veri != td.verification {
                t.Error("VerifyBytes fail")
            }

        })
    }

}

func Test_Vec_Check_secp256k1(t *testing.T) {
    for i, td := range testSigVec {
        t.Run(fmt.Sprintf("index %d", i), func(t *testing.T) {
            if len(td.secretKey) > 0 {
                priv, err := NewPrivateKey(secp256k1.S256(), td.secretKey)
                if err != nil {
                    t.Fatal(err)
                }

                pub := &priv.PublicKey

                pubBytes := pub.X.Bytes()

                // check publicKey
                if !bytes.Equal(pubBytes, td.publicKey) {
                    t.Errorf("PublicKey got: %x, want: %x", pubBytes, td.publicKey)
                }

                // do sig
                k := new(big.Int).SetBytes(td.auxRand)

                r, s, err := SignUsingKToRS(k, priv, sha256.New, td.message)
                if err != nil {
                    t.Error("SignUsingKToRS fail")
                }

                // check sig
                curveParams := secp256k1.S256().Params()
                p := curveParams.P

                plen := (p.BitLen() + 7) / 8
                qlen := (curveParams.BitSize + 7) / 8

                sig := make([]byte, plen + qlen)

                r.FillBytes(sig[:plen])
                s.FillBytes(sig[plen:])

                if !bytes.Equal(sig, td.signature) {
                    t.Errorf("sig fail, got: %x, want: %x", sig, td.signature)
                }

            }

            pubBytes := append([]byte{byte(3)}, td.publicKey...)

            x, y := elliptic.UnmarshalCompressed(secp256k1.S256(), pubBytes)
            if x == nil || y == nil {
                t.Fatal("publicKey error")
            }

            pubkey := &PublicKey{
                Curve: secp256k1.S256(),
                X: x,
                Y: y,
            }

            veri := VerifyBytes(pubkey, sha256.New, td.message, td.signature)
            if veri != td.verification {
                t.Error("VerifyBytes fail")
            }

        })
    }

}

// sha256, p256
type testVec struct {
    secretKey []byte
    publicKey []byte
    auxRand   []byte
    message   []byte
    signature []byte
    verification bool
}

var testSigVec = []testVec{
    {
        secretKey: fromHex("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"),
        publicKey: fromHex("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
        auxRand:   fromHex("01"),
        message:   fromHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
        signature: fromHex("6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"),
        verification: true,
    },
    {
        secretKey: fromHex("C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9"),
        publicKey: fromHex("DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8"),
        auxRand:   fromHex("C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906"),
        message:   fromHex("7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C"),
        signature: fromHex("5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7"),
        verification: true,
    },
    {
        secretKey: fromHex("0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710"),
        publicKey: fromHex("25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517"),
        auxRand:   fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        message:   fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        signature: fromHex("7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3"),
        verification: true,
    },

    {
        secretKey: fromHex("0340034003400340034003400340034003400340034003400340034003400340"),
        publicKey: fromHex("778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117"),
        auxRand:   fromHex("0000000000000000000000000000000000000000000000000000000000000000"),
        message:   fromHex(""),
        signature: fromHex("71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63"),
        verification: true,
    },
    {
        secretKey: fromHex("0340034003400340034003400340034003400340034003400340034003400340"),
        publicKey: fromHex("778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117"),
        auxRand:   fromHex("0000000000000000000000000000000000000000000000000000000000000000"),
        message:   fromHex("11"),
        signature: fromHex("08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF"),
        verification: true,
    },
    {
        secretKey: fromHex("0340034003400340034003400340034003400340034003400340034003400340"),
        publicKey: fromHex("778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117"),
        auxRand:   fromHex("0000000000000000000000000000000000000000000000000000000000000000"),
        message:   fromHex("0102030405060708090A0B0C0D0E0F1011"),
        signature: fromHex("5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5"),
        verification: true,
    },
    {
        secretKey: fromHex("0340034003400340034003400340034003400340034003400340034003400340"),
        publicKey: fromHex("778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117"),
        auxRand:   fromHex("0000000000000000000000000000000000000000000000000000000000000000"),
        message:   fromHex("99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999"),
        signature: fromHex("403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367"),
        verification: true,
    },

    // false data
    {
        secretKey: fromHex(""),
        publicKey: fromHex("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
        auxRand:   fromHex(""),
        message:   fromHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
        signature: fromHex("1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD"),
        verification: false,
    },
    {
        secretKey: fromHex(""),
        publicKey: fromHex("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
        auxRand:   fromHex(""),
        message:   fromHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
        signature: fromHex("6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6"),
        verification: false,
    },
}

