package kcdsa

import (
    "fmt"
    "bufio"
    "testing"
    "strings"
    "math/big"
    "crypto"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/hash/has160"
    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
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

var testBitsize = 256
var testProbability = 64

func Test_GenerateKey2(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    var priv PrivateKey
    err := GenerateParameters(&priv.PublicKey.Parameters, rand.Reader, A2048B224SHA224)
    assertError(err, "GenerateParameters-Error")

    err = GenerateKey(&priv, rand.Reader)
    assertError(err, "GenerateKey-Error")

    pri := &priv
    var _ crypto.Signer = pri

    assertNotEmpty(priv, "GenerateKey")
}

func Test_Sign(t *testing.T) {
    assertBool := cryptobin_test.AssertBoolT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    var priv PrivateKey
    err := GenerateParameters(&priv.PublicKey.Parameters, rand.Reader, A2048B224SHA224)
    assertError(err, "GenerateParameters-Error")

    err = GenerateKey(&priv, rand.Reader)
    assertError(err, "GenerateKey-Error")

    pub := &priv.PublicKey

    assertNotEmpty(priv, "Sign")

    data := []byte("123tesfd!dfsign")

    r, s, err := Sign(rand.Reader, &priv, sha256.New224, data)
    assertError(err, "Sign-sig-Error")

    veri := Verify(pub, sha256.New224, data, r, s)
    assertBool(veri, "Sign-veri")
}

func Test_SignBytes(t *testing.T) {
    assertBool := cryptobin_test.AssertBoolT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    var priv PrivateKey
    err := GenerateParameters(&priv.PublicKey.Parameters, rand.Reader, A2048B224SHA224)
    assertError(err, "GenerateParameters-Error")

    err = GenerateKey(&priv, rand.Reader)
    assertError(err, "GenerateKey-Error")

    pub := &priv.PublicKey

    assertError(err, "Sign-Error")
    assertNotEmpty(priv, "Sign")

    data := "123tesfd!dfsign"

    sig, err := SignBytes(rand.Reader, &priv, sha256.New, []byte(data))
    assertError(err, "Sign-sig-Error")

    veri := VerifyBytes(pub, sha256.New, []byte(data), sig)
    assertBool(veri, "Sign-veri-Error")
}

func Test_Sign2(t *testing.T) {
    assertBool := cryptobin_test.AssertBoolT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    var priv PrivateKey
    err := GenerateParameters(&priv.PublicKey.Parameters, rand.Reader, A2048B224SHA224)
    assertError(err, "GenerateParameters-Error")

    err = GenerateKey(&priv, rand.Reader)
    assertError(err, "GenerateKey-Error")

    pub := &priv.PublicKey

    assertNotEmpty(priv, "Sign")

    data := []byte("123tesfd!dfsign")

    sig, err := priv.Sign(rand.Reader, data, &SignerOpts{
        Hash: sha256.New224,
    })
    assertError(err, "Sign-sig-Error")

    veri, _ := pub.Verify(data, sig, &SignerOpts{
        Hash: sha256.New224,
    })
    assertBool(veri, "Sign-veri")
}

func test_GenerateKey(t *testing.T) *PrivateKey {
    assertError := cryptobin_test.AssertErrorT(t)

    var priv PrivateKey
    err := GenerateParameters(&priv.PublicKey.Parameters, rand.Reader, A2048B224SHA224)
    assertError(err, "GenerateParameters-Error")

    err = GenerateKey(&priv, rand.Reader)
    assertError(err, "GenerateKey-Error")

    return &priv
}

func Test_MarshalPKCS8(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)

    pri := test_GenerateKey(t)
    pub := &pri.PublicKey

    assertNotEmpty(pri, "MarshalPKCS8")

    //===============

    pubDer, err := MarshalPublicKey(pub)
    assertError(err, "MarshalPublicKey-pub-Error")
    assertNotEmpty(pubDer, "MarshalPublicKey")

    parsedPub, err := ParsePublicKey(pubDer)
    assertError(err, "ParsePublicKey-pub-Error")
    assertEqual(parsedPub, pub, "MarshalPKCS8")

    //===============

    priDer, err := MarshalPrivateKey(pri)
    assertError(err, "MarshalPrivateKey-pri-Error")
    assertNotEmpty(priDer, "MarshalPrivateKey")

    parsedPri, err := ParsePrivateKey(priDer)
    assertError(err, "ParsePrivateKey-pri-Error")
    assertEqual(parsedPri, pri, "ParsePrivateKey")
}

var testPkcs8Prikey_A2048B224SHA224 = `-----BEGIN PRIVATE KEY-----
MIICXAIBADCCAjQGBij0KAMAAjCCAigCggEBAIGlzMbS5uNZuutfAtmPIW5DrMiz
YyeT6TidPmmmDzOppmT7jHChGK33Qt+4XFhyugYxLQ5FeaT56+poMHwuFtiM3gb0
PXTOuN+9IcFkexd14oJOcKAA0RjoyT/hEliySw9s1ufeDGv3dLw8IBXxOSgzHB1+
RLneVNB5AaI2IpmzL+VlKXu7W8gpYF/+cskMRWQRXcwirpPbFgNhWeuBIS8qxGBS
xi6qABvCxWdi40MCfU4/bZNGXlPzqAEiZzQEoDMVBi6KPF2ghtvg0pslV+nAt7Ci
c3RoYnccfHMaH4VNmvGBU60AQnY66u+lQFUHz7dOHCZ2EaKn5Zit66zLHZECHQC3
9o8zUina0IkFeLsUjN+fr+mrdIzvnEihCdjdAoIBABga8aDsnHqYz5+UVJBpsZka
MmhWCHFPC2L2hj3T0Op8OHDyrrCeNSGdQWtEb4gnhhJeco7YFcjGyfIQNDx1fkgC
QM3LYY1yy+vCqjAT8+w6M73WkqEqXRUJ4t2RqUdDMPwW2vBnvwyTlzM9U0cfD/h8
/GVZgtF5AUGSSORDU7xZdkGandEPAKW64IalfMeqp46MVaBknSYf9zg0GxyjSMo/
zeVWJsCsXkBTuy80tM73VkFoTjCQjTchpcltQuNdqSoIOEeLw5CDoR5dHedUexWq
OPv9u2sxiQMf48C93FoVZhqTjbwflOdEZHdtTVReCB7kJbfYYY/QfjRNZDIyaRwE
HwIdALTmup4XHmfv3nPyFIcAHTgdpaipeiIRsKHnvks=
-----END PRIVATE KEY-----
`
var testPkcs8Prikey_A2048B224SHA256 = `-----BEGIN PRIVATE KEY-----
MIICXAIBADCCAjUGBij0KAMAAjCCAikCggEBAOnni3MmPBdaZziWkrnF4+v7AYPy
VPr2I+FF74nVAD0+kBJJDgbEwKol+C5wxKGZZOQFVYGZI4xdyEMVqQlM2b0aw01Y
Pc87Ou6HFlj4d5Wa4sbnrqSHLm9tLRbcb5pyk8Ei6xzqZaTtcjVHpeWRYYaC2/8I
jEKxRwPX+oGR0bAy34T6aps7SSOzB+8a3IlWkl8vtF2OuUGK6BrdRnUY4a4GKu+U
ODT0/+MKq8zVPGd/4kc89deISHmB3T5BM9P2wD3YJ6WdgfLOx7cqJnL4vzTwYat/
AKOx1QkAWJQ24WN+0cPkGOHhTeEjxmTLZAezgCdhX6dwAUWditR7N1EWuw0CHQD4
OVit7DDtVzPB57LIIpIloWyd5Cq+IO6UxWMHAoIBAQDZsxSefNphRqzuNTLTub9G
vAO30pvDO6OsyoWv4LE97t4N3vRttSPt2Lq+bGnl689yqjMeQNv1RnWUJ5/IxEDX
i4wL0Zfjafs6hGpdw56YbN3hC4TpG1few8j40ctgCIQ6LClWpabw3op5LnxhFOHr
AmiSw2zAIkfjw1fVeh/RXdJP05x649cTuBUNPxflFO0MdaF17VkIxaWVuLr+cDlm
wnWt6UQ3tZ5wgx4zRkr0IkVTSAfCtc7Z/0yp0veCSBBgzSqMaBKaUFxNRSgmIKlv
PkDb3XdE/6qSddIzPySI5bZYCgMBgASMxrAhQcwTEVuiqGdvzbgPj4c3qZbLB2w7
BB4CHGDEQHx/QkDW2r9jUtOkiKfeDmPViqvgU8d069o=
-----END PRIVATE KEY-----
`
var testPkcs8Prikey_A2048B256SHA256 = `-----BEGIN PRIVATE KEY-----
MIICZAIBADCCAjkGBij0KAMAAjCCAi0CggEBAMdnNfj6lnXo8wVPFerb6SExwhoF
GpTqZyPdNhUYQjiJQuE9njK7IW3T870iIbiyMX7Wj8bRub2iIv54A0Qv5yBuD2ZL
J/hhB1we9bQ4OczOYKSFLfcL++6aOqY4hpSImqSJrUv/bCQgYabmMsaUEBlUbClm
Gg5lXe+gOikyh1EDnapDj0Yehz6VPDFTFD5u1DMy+kyHzq8j1bgCBYkgRa93wz7q
jP/hhXnZCefW0zaNyF/CbXW77xcXDK4k4XT9aCpgec6kHH8sfjYvpkhpkgHGzn6f
Nql7pmROMge/X/30eSmcnZOdsVUmmUqYXSQvN10f6iNFYR50BL1bffxtY4sCIQC6
UaWMXGdZ800kfQiHnHsAR7/MJp+0RjKTpEHsqNPTxQKCAQEApQsu1nm9kFKY9kfI
TGp2opcEICxODSxHsyf3z0KUZxu1MjCPtQDv/YDxwMKafKHGmgguGS0qKojtfdvc
h07KYG4eTYcR3aCyhUxl0yxq/C8iUH8vDCuI6MzkaPwKL8+NnaTiBIoT7t/7uCOX
oWi4jQaYBTwaRD786XAsjfAu9PotTHxenp+q9hpRYXukdJA34ER7MRwrrG1RUDfK
n5nh3bdseeTKjDJYwcaSoRebl6OgIJEW65vIAsHQoKMG/QRYa3r+A3lxZsg0t6M9
Fe3OBS2GdHTfkhS9wLQMNnLgK3jjo3g9PzHXnEjFgDMSIH3nmxjSX1wipQ1Fk+h3
YHy0EwQiAiAeArcCNQ4OZdp8MCZ22diTWqg7qnsBwRPCZrwGI23UHg==
-----END PRIVATE KEY-----
`
var testPkcs8Prikey_A3072B256SHA256 = `-----BEGIN PRIVATE KEY-----
MIIDYwIBADCCAzgGBij0KAMAAjCCAywCggGBAKmwZel6EDJwZBapP0Z8DhoF7ETZ
nkVRFeKipBJN76SQ4HWOk97oDeCqMjcsE+OuBTp8cKxMJQ3RTZ2PF1lJMiMA/U1M
lI5XFdDaoPTS7vBgUnImoH25VovHb2Fi3vrmUxG1IMM6C2/NiP4KdvWEP101tzAu
5mCJoPFqbxOfviH0irMb03Zj6abCTJgovbqSqDGPdI8QSQGr7PoeXBZ3L11rYT/c
aSlp1hyeMNxGysctAtrUUzjuCmSLuPZiXKc+wWhphFQZUZbdxlHshcbQ4XITSQmq
dcnGDfgOFC0G0Zmo1FilWmaltQsCbmDNpy+5zKsaTLTi7v9dQRhOOvJjhLO2AH0b
YNE0eRiNp+CKKuTWlIqCs4AhJOJ7/J2UiV93Ys1FGfXeVEBs/fDW0BA+AwZwRAwB
g808kdip/gA2alkCrd1ttushp438f5vWKvXm6U6R+b/IdbikWR5QiFtYSvH+jHOP
8nXzekePRgteW/heVycJ6Dvw8R7edLrfGu5tqQIhAPfw9ykkCfFzwXNzxUwj85+F
7H+HUibSyjT0ckVYylP/AoIBgDCwJoU1W65OnQ9lOI1XSZmXpqOy2nwOKBXGjsAh
ATX/4rpvuU4b5Bq4iyC4mgoR7Quie7HrUhTGWF5dAEBX9hIstxo3ityMVKl8/jtJ
JUixXtNtDcuypnRiI/S0O+nFNGzEdmKMB8K+S42guCkqRer+ZAfhwbedjeoD2WZ3
GuCBGSkcA8pqk1CIiEzSyuuXbFX+8g98teOs4aQ09FkaA0U8UvEuhM4iaX7JWcA3
Vp43cCApe7b+g8CgHu1C0Wubzgq+OsvLBSeZpJAnd6Lu4fYCtOSo/Bo1F2n8iVZY
10KfyNVn+BP24a4AGDLy9LP/VIrq+X7IX1J7Dl/X5YBTiuFMcDpSkskb1sUZs/J2
tj0cLHvUg9gOvJbLOsmZnooiC2ZANNv7jMppWzPXApaLukh57jFY2rHJDT/s9NFC
B/S05hvOnF1ZWfJGMI6rkvwk9/q7M7o/rC6sun245w8jRDnmuwcn7063TkBMmQSq
zKeLJGapbISAVeeUuiOZemfoLAQiAiAs53f8PRQsj1erKkExldtKuOxv/oP55rf3
kwITuibkYw==
-----END PRIVATE KEY-----
`
var testPkcs8Prikey_A1024B160HAS160 = `-----BEGIN PRIVATE KEY-----
MIIBSQIBADCCASoGBij0KAMAAjCCAR4CgYEA08uPCA8Aa99kMcnNG5UXKAH7BLAw
aUkypOE3744maQSWzrTeQTg3jU5YPwlac99sNIMH5561FNliG4TaX1kK29k7Mkf5
DHG9l3bZoB6eLY3lJmGzh+OJ1V28s9ACFxPJ4pVcUBNOqZWFtlvHImqmOuvDy2Cp
lg6y3RuEi0BC/a8CFQCZX8dvX/YxQm3gHN+cXJxQVCJ74QKBgHTwhmgt5J8TPacG
ZR6Br3efcakRJOHNcNl+6kM4vgy1fem6Ja0ZU1T4L2aj/dYKcGY8gV9VkS2Wntoo
RKTJ+B5IbyZVCCA7WFcnY8JFGOtCfbXWdg/C1cx/cP5oRREwZ5+mcz61fCbasLU+
cF3lZfYe+sz9GGIipjkjFaUZuAo3BBYCFFDgTDnugC+5OTvXLE99OPgYNFpR
-----END PRIVATE KEY-----
`

func Test_PrivateKey_Check(t *testing.T) {
    t.Run("A2048B224SHA224", func(t *testing.T) {
        test_PrivateKey_Check(t, testPkcs8Prikey_A2048B224SHA224)
    })
    t.Run("A2048B224SHA256", func(t *testing.T) {
        test_PrivateKey_Check(t, testPkcs8Prikey_A2048B224SHA256)
    })
    t.Run("A2048B256SHA256", func(t *testing.T) {
        test_PrivateKey_Check(t, testPkcs8Prikey_A2048B256SHA256)
    })
    t.Run("A3072B256SHA256", func(t *testing.T) {
        test_PrivateKey_Check(t, testPkcs8Prikey_A3072B256SHA256)
    })
    t.Run("A1024B160HAS160", func(t *testing.T) {
        test_PrivateKey_Check(t, testPkcs8Prikey_A1024B160HAS160)
    })
}

func test_PrivateKey_Check(t *testing.T, pemStr string) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    pri := decodePEM(pemStr)

    priv, err := ParsePrivateKey(pri)
    if err != nil {
        t.Fatal(err)
    }

    assertError(err, "PrivateKeyCheck")
    assertNotEmpty(priv, "PrivateKeyCheck")

    privDer, err := MarshalPrivateKey(priv)
    if err != nil {
        t.Fatal(err)
    }

    assertNotEmpty(privDer, "PrivateKeyCheck")
}

var rnd = bufio.NewReaderSize(rand.Reader, 1<<15)

type testCase struct {
    Sizes ParameterSizes
    Hash Hasher

    M []byte

    Seedb []byte
    J     *big.Int
    Count int
    P, Q  *big.Int

    H []byte
    G *big.Int

    XKEY []byte
    X    *big.Int
    Y, Z *big.Int

    KKEY *big.Int
    R    *big.Int
    S    *big.Int

    Fail bool
}

func Test_SignVerify_With_BadPublicKey(t *testing.T) {
    for idx, tc := range testCaseTTAK {
        tc2 := testCaseTTAK[(idx+1)%len(testCaseTTAK)]

        pub := PublicKey{
            Parameters: Parameters{
                P: tc2.P,
                Q: tc2.Q,
                G: tc2.G,
            },
            Y: tc2.Y,
        }

        ok := Verify(&pub, tc.Hash, tc.M, tc.R, tc.S)
        if ok {
            t.Errorf("Verify unexpected success with non-existent mod inverse of Q")
            return
        }
    }
}

func Test_Signing_With_DegenerateKeys(t *testing.T) {
    badKeys := []struct {
        p, q, g, y, x string
    }{
        {"00", "01", "00", "00", "00"},
        {"01", "ff", "00", "00", "00"},
    }

    msg := []byte("testing")
    for i, test := range badKeys {
        priv := PrivateKey{
            PublicKey: PublicKey{
                Parameters: Parameters{
                    P: toBigint(test.p),
                    Q: toBigint(test.q),
                    G: toBigint(test.g),
                },
                Y: toBigint(test.y),
            },
            X: toBigint(test.x),
        }

        if _, _, err := Sign(rand.Reader, &priv, sha256.New224, msg); err == nil {
            t.Errorf("#%d: unexpected success", i)
            return
        }
    }
}

func Test_KCDSA(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping parameter generation test in short mode")
    }

    t.Run("A2048B224SHA224", testKCDSA(A2048B224SHA224, sha256.New224))
    t.Run("A2048B224SHA256", testKCDSA(A2048B224SHA256, sha256.New))
    t.Run("A2048B256SHA256", testKCDSA(A2048B256SHA256, sha256.New))
    t.Run("A3072B256SHA256", testKCDSA(A3072B256SHA256, sha256.New))
    t.Run("A1024B160HAS160", testKCDSA(A1024B160HAS160, has160.New))
}

func testKCDSA(sizes ParameterSizes, h Hasher) func(*testing.T) {
    return func(t *testing.T) {
        d, ok := GetSizes(sizes)
        if !ok {
            t.Errorf("domain not found")
            return
        }

        var priv PrivateKey
        params := &priv.Parameters

        err := GenerateParameters(params, rand.Reader, sizes)
        if err != nil {
            t.Error(err)
            return
        }

        if params.P.BitLen() > d.A {
            t.Errorf("params.BitLen got:%d want:%d", params.P.BitLen(), d.A)
            return
        }

        if params.Q.BitLen() > d.B {
            t.Errorf("q.BitLen got:%d want:%d", params.Q.BitLen(), d.B)
            return
        }

        err = GenerateKey(&priv, rand.Reader)
        if err != nil {
            t.Errorf("error generating key: %s", err)
            return
        }

        testSignAndVerify(t, &priv, h)
        testSignAndVerifyASN1(t, &priv, h)
    }
}

func testSignAndVerify(t *testing.T, priv *PrivateKey, h Hasher) {
    data := []byte("testing")
    r, s, err := Sign(rand.Reader, priv, h, data)
    if err != nil {
        t.Errorf("error signing: %s", err)
        return
    }

    ok := Verify(&priv.PublicKey, h, data, r, s)
    if !ok {
        t.Error("Verify failed")
        return
    }

    data[0] ^= 0xff
    if Verify(&priv.PublicKey, h, data, r, s) {
        t.Errorf("Verify always works!")
    }
}

func testSignAndVerifyASN1(t *testing.T, priv *PrivateKey, h Hasher) {
    data := []byte("testing")
    sig, err := SignASN1(rand.Reader, priv, h, data)
    if err != nil {
        t.Errorf("error signing: %s", err)
        return
    }

    if !VerifyASN1(&priv.PublicKey, h, data, sig) {
        t.Errorf("VerifyASN1 failed")
    }

    data[0] ^= 0xff
    if VerifyASN1(&priv.PublicKey, h, data, sig) {
        t.Errorf("VerifyASN1 always works!")
    }
}

func verifyTestCases(t *testing.T, testCases []testCase) {
    for i, tc := range testCases {
        t.Run(fmt.Sprintf("test index %d", i), func(t *testing.T) {
            pub := PublicKey{
                Parameters: Parameters{
                    P: tc.P,
                    Q: tc.Q,
                    G: tc.G,
                },
                Y: tc.Y,
            }

            ok := Verify(&pub, tc.Hash, tc.M, tc.R, tc.S)
            if ok == tc.Fail {
                t.Errorf("verify failed")
                return
            }
        })
    }
}
