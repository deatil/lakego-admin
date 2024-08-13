package eckcdsa

import (
    "fmt"
    "hash"
    "bytes"
    "bufio"
    "math/big"
    "strings"
    "crypto"
    "testing"
    "crypto/rand"
    "crypto/sha256"
    "crypto/elliptic"
    "encoding/hex"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/elliptic/nist"
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

var rnd = bufio.NewReaderSize(rand.Reader, 1<<15)

type testCase struct {
    curve elliptic.Curve
    hash  hash.Hash

    D  *big.Int
    Qx *big.Int
    Qy *big.Int

    K *big.Int

    M []byte
    R *big.Int
    S *big.Int

    Fail bool
}

var (
    p224     = elliptic.P224()
    p256     = elliptic.P256()
    secp224r = elliptic.P224()
    secp256r = elliptic.P256()

    b233     = nist.B233()
    k233     = nist.K233()
    b283     = nist.B283()
    k283     = nist.K283()
    sect233r = nist.B233()
    sect233k = nist.K233()
    sect283r = nist.B283()
    sect283k = nist.K283()

    hashSHA256     = sha256.New()
    hashSHA256_224 = sha256.New224()
)

func testVerify(t *testing.T, testCases []testCase, curve elliptic.Curve, hash hash.Hash) {
    for idx, tc := range testCases {
        key := PublicKey{
            Curve: curve,
            X:     tc.Qx,
            Y:     tc.Qy,
        }

        ok := VerifyWithRS(&key, hash, tc.M, tc.R, tc.S)
        if ok == tc.Fail {
            t.Errorf("%d: Verify failed, got:%v want:%v\nM=%s", idx, ok, !tc.Fail, hex.EncodeToString(tc.M))
            return
        }
    }
}

func testSignVerify(t *testing.T, testCases []testCase) {
    R, S := new(big.Int), new(big.Int)
    var ok bool
    var err error

    for idx, tc := range testCases {
        key := PrivateKey{
            PublicKey: PublicKey{
                Curve: tc.curve,
                X:     tc.Qx,
                Y:     tc.Qy,
            },
            D: tc.D,
        }

        R, S, err = signUsingK(tc.K, &key, tc.hash, tc.M)
        if err != nil {
            t.Errorf("%d: error signing: invalid K", idx)
            return
        }

        if R.Cmp(tc.R) != 0 || S.Cmp(tc.S) != 0 {
            t.Errorf("%d: error signing: (r, s)", idx)
            return
        }

        ok = VerifyWithRS(&key.PublicKey, tc.hash, tc.M, tc.R, tc.S)
        if ok == tc.Fail {
            t.Errorf("%d: Verify failed, got:%v want:%v\nM=%s", idx, ok, !tc.Fail, hex.EncodeToString(tc.M))
            return
        }
    }
}

func Test_SignVerify_With_BadPublicKey(t *testing.T) {
    for idx, tc := range testCase_TTAK {
        tc2 := testCase_TTAK[(idx+1)%len(testCase_TTAK)]

        key := PublicKey{
            Curve: tc2.curve,
            X:     tc2.Qx,
            Y:     tc2.Qy,
        }

        ok := VerifyWithRS(&key, tc.hash, tc.M, tc.R, tc.S)
        if ok {
            t.Errorf("%d: Verify unexpected success with non-existent mod inverse of Q", idx)
            return
        }
    }
}

func Test_ECKCDSA(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping parameter generation test in short mode")
    }

    t.Run("P224_SHA256_224", testKCDSA(p224, hashSHA256_224))
    t.Run("P224_SHA256_256", testKCDSA(p224, hashSHA256))

    t.Run("P256_SHA256_224", testKCDSA(p256, hashSHA256_224))
    t.Run("P256_SHA256_256", testKCDSA(p256, hashSHA256))

    if testing.Short() {
        return
    }

    t.Run("B233_SHA256_224", testKCDSA(b233, hashSHA256_224))
    t.Run("B233_SHA256_256", testKCDSA(b233, hashSHA256))

    t.Run("B283_SHA256_224", testKCDSA(b283, hashSHA256_224))
    t.Run("B283_SHA256_256", testKCDSA(b283, hashSHA256))

    t.Run("K233_SHA256_224", testKCDSA(k233, hashSHA256_224))
    t.Run("K233_SHA256_256", testKCDSA(k233, hashSHA256))

    t.Run("K283_SHA256_224", testKCDSA(k283, hashSHA256_224))
    t.Run("K283_SHA256_256", testKCDSA(k283, hashSHA256))
}

func Test_Signing_With_DegenerateKeys(t *testing.T) {
    // Signing with degenerate private keys should not cause an infinite
    // loop.
    badKeys := []struct {
        d, y, x string
    }{
        {"0000", "0001", "0101"},
        {"0100", "0f0f", "1010"},
    }

    for i, test := range badKeys {
        priv := PrivateKey{
            PublicKey: PublicKey{
                Curve: secp224r,
                X:     toBigint(test.x),
                Y:     toBigint(test.y),
            },
            D: toBigint(test.d),
        }

        data := []byte("testing")
        if _, err := Sign(rand.Reader, &priv, sha256.New(), data); err == nil {
            t.Errorf("#%d: unexpected success", i)
            return
        }
    }
}

func testKCDSA(
    curve elliptic.Curve,
    h hash.Hash,
) func(t *testing.T) {
    return func(t *testing.T) {
        priv, err := GenerateKey(curve, rand.Reader)
        if err != nil {
            t.Errorf("error generating key: %s", err)
            return
        }

        testSignAndVerify(t, priv, h)
        testSignAndVerifyASN1(t, priv, h)
    }
}

func testSignAndVerify(
    t *testing.T,
    priv *PrivateKey,
    h hash.Hash,
) {
    data := []byte("testing")
    r, s, err := SignToRS(rand.Reader, priv, h, data)
    if err != nil {
        t.Errorf("error signing: %s", err)
        return
    }

    ok := VerifyWithRS(&priv.PublicKey, h, data, r, s)
    if !ok {
        t.Errorf("Verify failed")
        return
    }

    data[0] ^= 0xff
    if VerifyWithRS(&priv.PublicKey, h, data, r, s) {
        t.Errorf("Verify always works!")
    }
}

func testSignAndVerifyASN1(t *testing.T, priv *PrivateKey, h hash.Hash) {
    data := []byte("testing")
    sig, err := Sign(rand.Reader, priv, h, data)
    if err != nil {
        t.Errorf("error signing: %s", err)
        return
    }

    if !Verify(&priv.PublicKey, h, data, sig) {
        t.Errorf("VerifyASN1 failed")
    }

    data[0] ^= 0xff
    if Verify(&priv.PublicKey, h, data, sig) {
        t.Errorf("VerifyASN1 always works!")
    }
}

func Test_Sign_Verify_TTAK(t *testing.T) {
    testSignVerify(t, testCase_TTAK)
}

var (
    UserProvidedRandomInput = fromHex(`
        73616C64 6A666177 70333939 75333734 72303938 7539385E 255E2568 6B72676E
        3B6C776B 72703437 74393363 25243839 34333938 35396B6A 646D6E76 636D2063
        766B206F 34753039 7220346A 206F6A32 6F757432 30397866 71773B6C 2A26215E
        23405523 2A232429 2823207A 20786F39 35377463 2D393520 35207635 6F697576
        39383736 20362076 6A206F35 6975762D 3035332C 6D63766C 726B6677 6F726574`)

    M = fromHex(`
        54686973 20697320 61207361 6D706C65 206D6573 73616765 20666F72 2045432D
        4B434453 4120696D 706C656D 656E7461 74696F6E 2076616C 69646174 696F6E2E`)

    testCase_TTAK = []testCase{
        // Ⅱ.1 secp224r with SHA-224
        // p. 38
        {
            M:     M,
            curve: secp224r,
            hash:  hashSHA256_224,
            D:     toBigint(`562A6F64 E162FFCB 51CD4707 774AE366 81B6CEF2 05FE5D43 912956A2`),
            Qx:    toBigint(`B574169E 4FCEF1AF 3429D8BB 5481FF7D FA978690 492E1098 B80A5579`),
            Qy:    toBigint(`1576819B D9F0B685 19EE844A FE88CCFB 2AD574A5 6472D954 1461AE7E`),
            K:     toBigint(`76A0AFC1 8646D1B6 20A079FB 223865A7 BCB447F3 C03A35D8 78EA4CDA`),
            R:     toBigint(`EEA58C91 E0CDCEB5 799B00D2 412D928F DD23122A 1C2BDF43 C2F8DAFA`),
            S:     toBigint(`AEBAB53C 7A44A8B2 2F35FDB9 DE265F23 B89F65A6 9A8B7BD4 061911A6`),
        },
        // Ⅱ.2 secp224r with SHA-256
        // p. 40
        {
            M:     M,
            curve: secp224r,
            hash:  hashSHA256,
            D:     toBigint(`61585827 449DBC0E C161B2CF 8575C9DF 149F41DD 0289BE4F F110773D`),
            Qx:    toBigint(`CFA3A0C1 F4A0903E 84F314B0 70FB3EFA 531DB6D3 86739E01 2609557C`),
            Qy:    toBigint(`FDB53330 B727A7B3 D40E332B 59AF060C 957D908D 18862159 F92B26B3`),
            K:     toBigint(`EEC79D8D 4648DF3A 832A66E3 775537E0 00CC9B95 7E1319C5 DB9DD4F7`),
            R:     toBigint(`64B49E97 7E6534F8 77CB68A3 806F6A98 9311CEAA 8A64A055 8077C04B`),
            S:     toBigint(`AFF23D40 B1779511 51BE32F6 561B1B73 9E3E8F82 2CC52D4C B3909A93`),
        },
        // Ⅱ.3 secp256r with SHA-256
        // p. 42
        {
            M:     M,
            curve: secp256r,
            hash:  hashSHA256,
            D:     toBigint(`9051A275 AA4D9843 9EDDED13 FA1C6CBB CCE775D8 CC9433DE E69C5984 8B3594DF`),
            Qx:    toBigint(`148EDDD3 734FD5F1 5987579F 516089A8 C9FEF4AB 76B59D7B 8A01CDC5 6C4EDFDF`),
            Qy:    toBigint(`A4E2E42C B4372A6F 2F3F71A1 49481549 F68D2963 539C853E 46B94696 569E8D61`),
            K:     toBigint(`71B88F39 8916DA9C 90F555F1 B5732B7D C636B49C 638150BA C11BF05C FE16596A`),
            R:     toBigint(`0EDDF680 601266EE 1DA83E55 A6D9445F C781DAEB 14C765E7 E5D0CDBA F1F14A68`),
            S:     toBigint(`9B333457 661C7CF7 41BDDBC0 835553DF BB37EE74 F53DB699 E0A17780 C7B6F1D0`),
        },
        // Ⅱ.4 sect233r with SHA-224
        // p. 45
        {
            M:     M,
            curve: sect233r, // sect233r, Also known as: B-233, wap-wsg-idm-ecid-wtls11, ansit233r1
            hash:  hashSHA256_224,
            D:     toBigint(`00BF 83825505 3DBF499C BE190DE3 5BC14AFC 1EA142F3 5EE69838 5B48D688`),
            Qx:    toBigint(`01F4 85A65E59 B336E140 1C8A311F 01C92626 C663E69F 12A627E5 3E8F0675`),
            Qy:    toBigint(`01BF 338CE75A DFB07DEB D962E1D8 0C101587 269AC995 1B40422B 12E9DA3E`),
            K:     toBigint(`00F4 F088192E 8EB1CD8B 4ECB3A53 33746B40 EBF16966 A213B18A 176B2F62`),
            R:     toBigint(`     82EF9427 4AC70A3D AC231E38 AE0F0D31 8FD8E189 EE40A3E0 61EC80BF`),
            S:     toBigint(`00A8 CD7F7573 BAC3C4C4 00F65FDC CCD46F58 EBFC54CE 45571075 FD7704DB`),
        },
        // Ⅱ.5 sect233r with SHA-256
        // p. 47
        {
            M:     M,
            curve: sect233r,
            hash:  hashSHA256,
            D:     toBigint(`000E D21C5C28 5F2B454A 0FE5D97C 6A86AA3F 7CB14FFD D35EB089 BE11F031`),
            Qx:    toBigint(`0068 A50FAF91 43203612 1C5B6D2C 9307EA20 1FFE6F74 E09EF223 0AEC930F`),
            Qy:    toBigint(`0052 67430AF3 EF4FB190 A4430F26 9521D7FC E007E221 245F5D14 C7541963`),
            K:     toBigint(`0000 A516B3AD 24EB7F85 4D101DDF AB5A09A9 9D2C566A 09B29E57 2DAFDE75`),
            R:     toBigint(`E1C9 75FBD0E8 98FDB018 61C4EC8D 4CEAE19B 8CFCBBC8 09EF3A03 AD3A853A`),
            S:     toBigint(`00EF 7A6CAA2B 46D5BE07 DB837779 49F2505C 877FC475 76A54D40 BCD53D5F`),
        },
        // Ⅱ.6 sect233k with SHA-224
        // p. 49
        {
            M:     M,
            curve: sect233k,
            hash:  hashSHA256_224,
            D:     toBigint(`0073 6439374F 72B1C723 AE611CB3 DFBCA0A8 E2C5096B DB9C2D37 21167B49`),
            Qx:    toBigint(`01E9 1DEFBD41 AE655105 E046E03E C13E3860 0E9A2C9A 920B8E75 53721605`),
            Qy:    toBigint(`0112 9C2706D1 9D134891 C7BAD84A 5600C2AF F86068C4 7497F5BD 498D0B76`),
            K:     toBigint(`0061 7AA0B7A8 197A2B81 01500BFE 55D5322A 7149E275 F91ADBC7 E30128E4`),
            R:     toBigint(`     B164A12F 615CC661 C10B78CB 6E01C9DE 46337C50 C036FAC5 51178752`),
            S:     toBigint(`  4A 2109081E B3ADF95C 19FFAE89 5D303B83 147B27C6 EFAE8536 2BFAB89A`),
        },
        // Ⅱ.7 sect233k with SHA-256
        // p. 52
        {
            M:     M,
            curve: sect233k,
            hash:  hashSHA256,
            D:     toBigint(`0028 13E18571 44BE8611 A7B93256 4EB3603D B08406A6 90D8185D EFE6EC5F`),
            Qx:    toBigint(`00CF 66347977 26F04185 BC953B3D DB4B9375 9D074522 0938DA29 DD7FA585`),
            Qy:    toBigint(`01E0 00F206CE D0896589 2BCFA3E7 B459CED4 7188EBDA 7A74B03E 2ECB66FC`),
            K:     toBigint(`0006 B64D5DB8 65FD5E32 72ABFDBA EF0964F1 C26546A0 1582A4AD E5C0C2CF`),
            R:     toBigint(`  D4 B2C6E695 9906C6A6 A8290AEF 7261FE96 EADCC177 63A1DE9D D009737C`),
            S:     toBigint(`  08 657B1F0C DFCDF279 A6433A8D 68BA2D02 244A4C34 8519A05F A2CF37ED`),
        },
        // Ⅱ.8 sect283r with SHA-256
        // p. 54
        {
            M:     M,
            curve: sect283r,
            hash:  hashSHA256,
            D:     toBigint(`00D64BEC 51F1ADA0 5BBD4F2B 53405B0C E8A1B99C D8DB6309 76A47F76 F08F205E EFC3FBD8`),
            Qx:    toBigint(`04313C7E 9C4F80D2 6A287B37 FE7FAA96 BE31F116 2E18BDB4 70CF43D4 DB28DE10 8B007E9F`),
            Qy:    toBigint(`0342CCF6 F502F9DF EC208170 24326C26 E867E1FB EC6634CB 17023CA0 222D6112 E0BFA106`),
            K:     toBigint(`00D18E44 CB7F75F8 01277FA5 CF31A268 8CC2F322 2FA9F26E E8598126 AFEEE4E3 8DD0E08E`),
            R:     toBigint(`         4A23BA73 B29A9010 ACD1E231 3B9A252C E209C7BF 3643926F A7BF8C87 A8C76D40`),
            S:     toBigint(`03AA4FFF F1F4C3EE BF9C8798 2E717572 71CB7662 BA03463B 8B5F97B0 5C7F7C2C 88A31799`),
        },
        // Ⅱ.9 sect283r with SHA-256
        // Memo: use sect283k not sect283r
        // p. 57
        {
            M:     M,
            curve: sect283k,
            hash:  hashSHA256,
            D:     toBigint(`014930E6 6B51F09F EEBBAFFC 9111C5CF 8AE406C9 35AC9618 F0A613B9 6D97F7DB 8F6EBA74`),
            Qx:    toBigint(`078A6ACD D5F779F2 5E8AB413 965E217F E6B1E63D 4717EEF5 0DC8C59D F7B1A095 BC3027AE`),
            Qy:    toBigint(`07B6D962 5F2D9DDF 516B5037 E1E7B115 26E12AC4 E65AD498 CD85D65A 9E915D58 6976C00F`),
            K:     toBigint(`01EA8FB5 72B7B2DA 7149DCD8 78101ECF 3F296400 E13A0D65 C8B6E558 C0237C6D A55268A1`),
            R:     toBigint(`         E214F3CF 8BBB6E92 F779E6C8 A3424BA8 64734002 5EB49EED C6016746 81B14AFD`),
            S:     toBigint(`0014CC0B B9245B7A 8BC3C6E0 392AAACE DCED8A61 9D9676E9 73D5244D 7F45E01D B425A93E`),
        },
    }
)

func Test_PKCS8PrivateKey(t *testing.T) {
    test_PKCS8PrivateKey(t, elliptic.P224())
    test_PKCS8PrivateKey(t, elliptic.P256())
    test_PKCS8PrivateKey(t, elliptic.P384())
    test_PKCS8PrivateKey(t, elliptic.P521())
}

func test_PKCS8PrivateKey(t *testing.T, curue elliptic.Curve) {
    t.Run(fmt.Sprintf("%s", curue), func(t *testing.T) {
        priv, err := GenerateKey(curue, rand.Reader)
        if err != nil {
            t.Fatal(err)
        }

        pub := priv.Public().(*PublicKey)

        pubDer, err := MarshalPublicKey(pub)
        if err != nil {
            t.Fatal(err)
        }
        privDer, err := MarshalPrivateKey(priv)
        if err != nil {
            t.Fatal(err)
        }

        if len(privDer) == 0 {
            t.Error("expected export key Der error: priv")
        }
        if len(pubDer) == 0 {
            t.Error("expected export key Der error: pub")
        }

        newPub, err := ParsePublicKey(pubDer)
        if err != nil {
            t.Fatal(err)
        }
        newPriv, err := ParsePrivateKey(privDer)
        if err != nil {
            t.Fatal(err)
        }

        if !newPriv.Equal(priv) {
            t.Error("Marshal privekey error")
        }
        if !newPub.Equal(pub) {
            t.Error("Marshal public error")
        }
    })
}

func Test_PKCS1PrivateKey(t *testing.T) {
    test_PKCS1PrivateKey(t, elliptic.P224())
    test_PKCS1PrivateKey(t, elliptic.P256())
    test_PKCS1PrivateKey(t, elliptic.P384())
    test_PKCS1PrivateKey(t, elliptic.P521())
}

func test_PKCS1PrivateKey(t *testing.T, curue elliptic.Curve) {
    t.Run(fmt.Sprintf("%s", curue), func(t *testing.T) {
        priv, err := GenerateKey(curue, rand.Reader)
        if err != nil {
            t.Fatal(err)
        }

        privDer, err := MarshalECPrivateKey(priv)
        if err != nil {
            t.Fatal(err)
        }

        if len(privDer) == 0 {
            t.Error("expected export key Der error: EC priv")
        }

        newPriv, err := ParseECPrivateKey(privDer)
        if err != nil {
            t.Fatal(err)
        }

        if !newPriv.Equal(priv) {
            t.Error("Marshal EC privekey error")
        }
    })
}

func Test_PKCS8PrivateKey_Check(t *testing.T) {
    for i, tc := range eckcdsaTestCases {
        t.Run(fmt.Sprintf("EC-KCDSA index %d", i), func(t *testing.T) {
            expectedDER := decodePEM(tc.pkcs8PrivateKey)

            actualDER, err := MarshalPrivateKey(&tc.key)
            if err != nil {
                t.Error(err)
                return
            }
            if !bytes.Equal(expectedDER, actualDER) {
                t.Errorf("Not equal: want %x, got %x", expectedDER, actualDER)
                return
            }

            key, err := ParsePrivateKey(expectedDER)
            if err != nil {
                t.Error(err)
                return
            }
            if !tc.key.Equal(key) {
                t.Errorf("ParsePKCS8PrivateKey fail")
                return
            }

            pubDER := decodePEM(tc.pkixPublicKey)
            _, err = ParsePublicKey(pubDER)
            if err != nil {
                t.Error(err)
                return
            }

        })
    }

}

// botan 3.4.0
var eckcdsaTestCases = []struct {
    pkcs8PrivateKey string
    pkixPublicKey   string
    key             PrivateKey
}{
    // botan keygen --algo=ECKCDSA --params=secp224r1 | tee priv.pem; botan pkcs8 --pub-out priv.pem | tee pub.pem
    {
        pkcs8PrivateKey: `-----BEGIN PRIVATE KEY-----
MHcCAQAwDwYGKPQoAwAFBgUrgQQAIQRhMF8CAQEEHKGO4n52vJYGADJX0ytFEDJk
iStPjgke8MhAnS6hPAM6AAQjp8EUqF9GDtVu6pvRJKP/Uc74B6w+bIo4DOozfIKd
DHPkzzJR5H+DsoghcXuW2dwubS2CNWynYA==
-----END PRIVATE KEY-----`,
        pkixPublicKey: `-----BEGIN PUBLIC KEY-----
ME0wDwYGKPQoAwAFBgUrgQQAIQM6AAQjp8EUqF9GDtVu6pvRJKP/Uc74B6w+bIo4
DOozfIKdDHPkzzJR5H+DsoghcXuW2dwubS2CNWynYA==
-----END PUBLIC KEY-----`,
        key: PrivateKey{
            D: toBigint("a18ee27e76bc9606003257d32b45103264892b4f8e091ef0c8409d2e"),
            PublicKey: PublicKey{
                Curve: elliptic.P224(),
                X:     toBigint("23a7c114a85f460ed56eea9bd124a3ff51cef807ac3e6c8a380cea33"),
                Y:     toBigint("7c829d0c73e4cf3251e47f83b28821717b96d9dc2e6d2d82356ca760"),
            },
        },
    },
    // botan keygen --algo=ECKCDSA --params=secp256r1 | tee priv.pem; botan pkcs8 --pub-out priv.pem | tee pub.pem
    {
        pkcs8PrivateKey: `-----BEGIN PRIVATE KEY-----
MIGGAgEAMBIGBij0KAMABQYIKoZIzj0DAQcEbTBrAgEBBCBfzTBIptZrYgMElRZP
4vz4XZ1GpJZQ3RNTwZGwvKN1aKFEA0IABJH7JLk0GeLqE/nk1dToZv07Cnhi++ii
ozxhUPAxUxVKYJnHp/O/tv29YQqo/OsxCBeGe3XRsZ160M586yjYknQ=
-----END PRIVATE KEY-----`,
        pkixPublicKey: `-----BEGIN PUBLIC KEY-----
MFgwEgYGKPQoAwAFBggqhkjOPQMBBwNCAASR+yS5NBni6hP55NXU6Gb9Owp4Yvvo
oqM8YVDwMVMVSmCZx6fzv7b9vWEKqPzrMQgXhnt10bGdetDOfOso2JJ0
-----END PUBLIC KEY-----`,
        key: PrivateKey{
            D: toBigint(`5fcd3048a6d66b62030495164fe2fcf85d9d46a49650dd1353c191b0bca37568`),
            PublicKey: PublicKey{
                Curve: elliptic.P256(),
                X:     toBigint(`91fb24b93419e2ea13f9e4d5d4e866fd3b0a7862fbe8a2a33c6150f03153154a`),
                Y:     toBigint(`6099c7a7f3bfb6fdbd610aa8fceb310817867b75d1b19d7ad0ce7ceb28d89274`),
            },
        },
    },
    // botan keygen --algo=ECKCDSA --params=secp384r1 | tee priv.pem; botan pkcs8 --pub-out priv.pem | tee pub.pem
    {
        pkcs8PrivateKey: `-----BEGIN PRIVATE KEY-----
MIG1AgEAMA8GBij0KAMABQYFK4EEACIEgZ4wgZsCAQEEMKzWMQ0u7Tubb9O96Bqd
bEYvvwyBa71c3+06nv2pAYKbEoLmtCK2FiZgWqNqJrRMHaFkA2IABKkE7RDKE7H8
L1zphOa88yFYtCJCH2GXBQUjgEjJpN/UKJFg8bUnmi6y7gFhwUIzTAzC9rNsUgFO
/QNWmSS09YF3TsUSfWtLByMjdkUbtySFLfCBAABMkvUVIxu7u2UWgA==
-----END PRIVATE KEY-----`,
        pkixPublicKey: `-----BEGIN PUBLIC KEY-----
MHUwDwYGKPQoAwAFBgUrgQQAIgNiAASpBO0QyhOx/C9c6YTmvPMhWLQiQh9hlwUF
I4BIyaTf1CiRYPG1J5ousu4BYcFCM0wMwvazbFIBTv0DVpkktPWBd07FEn1rSwcj
I3ZFG7ckhS3wgQAATJL1FSMbu7tlFoA=
-----END PUBLIC KEY-----`,
        key: PrivateKey{
            D: toBigint(`acd6310d2eed3b9b6fd3bde81a9d6c462fbf0c816bbd5cdfed3a9efda901829b1282e6b422b61626605aa36a26b44c1d`),
            PublicKey: PublicKey{
                Curve: elliptic.P384(),
                X:     toBigint(`a904ed10ca13b1fc2f5ce984e6bcf32158b422421f61970505238048c9a4dfd4289160f1b5279a2eb2ee0161c142334c`),
                Y:     toBigint(`0cc2f6b36c52014efd03569924b4f581774ec5127d6b4b07232376451bb724852df08100004c92f515231bbbbb651680`),
            },
        },
    },
    // botan keygen --algo=ECKCDSA --params=secp521r1 | tee priv.pem; botan pkcs8 --pub-out priv.pem | tee pub.pem
    {
        pkcs8PrivateKey: `-----BEGIN PRIVATE KEY-----
MIHsAgEAMA8GBij0KAMABQYFK4EEACMEgdUwgdICAQEEQUtbQZgG1KgW5+vfDHba
C0SBt9fTSgOnr1QvO8uITdiHfQEhX8+DOU//N4P/8oBDtQC8j6JtOih5u8aAk74x
HEzGoYGJA4GGAAQAefecYcZR/FSSAEJd/olys3HXJBZuGAMFOBaQim8InjrJb1aG
/BYjZBxQjYA5IghsPLHMFEjCtgj/DZNYxwNXHyUBP5ZpUuVOzvuzl2RpNnHoiatL
JtJRwVk+Gzlfid5XvvIS9p3byc3gw/pIubiQ2uR59mmHsFKZBlyVeX0oCmd5tNo=
-----END PRIVATE KEY-----`,
        pkixPublicKey: `-----BEGIN PUBLIC KEY-----
MIGaMA8GBij0KAMABQYFK4EEACMDgYYABAB595xhxlH8VJIAQl3+iXKzcdckFm4Y
AwU4FpCKbwieOslvVob8FiNkHFCNgDkiCGw8scwUSMK2CP8Nk1jHA1cfJQE/lmlS
5U7O+7OXZGk2ceiJq0sm0lHBWT4bOV+J3le+8hL2ndvJzeDD+ki5uJDa5Hn2aYew
UpkGXJV5fSgKZ3m02g==
-----END PUBLIC KEY-----`,
        key: PrivateKey{
            D: toBigint(`04b5b419806d4a816e7ebdf0c76da0b4481b7d7d34a03a7af542f3bcb884dd8877d01215fcf83394fff3783fff28043b500bc8fa26d3a2879bbc68093be311c4cc6`),
            PublicKey: PublicKey{
                Curve: elliptic.P521(),
                X:     toBigint(`079f79c61c651fc549200425dfe8972b371d724166e1803053816908a6f089e3ac96f5686fc1623641c508d803922086c3cb1cc1448c2b608ff0d9358c703571f25`),
                Y:     toBigint(`13f966952e54ecefbb39764693671e889ab4b26d251c1593e1b395f89de57bef212f69ddbc9cde0c3fa48b9b890dae479f66987b05299065c95797d280a6779b4da`),
            },
        },
    },
}
