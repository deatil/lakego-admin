package e521

import (
    "fmt"
    "bytes"
    "testing"
    "crypto"
    "crypto/rand"
    "crypto/elliptic"
    "encoding/pem"
    "encoding/hex"

    "github.com/deatil/go-cryptobin/elliptic/e521"
    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
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
    var _ crypto.Signer = (*PrivateKey)(nil)
}

func Test_SignerInterface(t *testing.T) {
    priv, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    var _ crypto.Signer = priv
    var _ crypto.PublicKey = pub
}

func Test_NewPrivateKey(t *testing.T) {
    priv, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    privBytes := PrivateKeyTo(priv)
    priv2, err := NewPrivateKey(privBytes)
    if err != nil {
        t.Fatal(err)
    }

    cryptobin_test.Equal(t, priv2, priv, "NewPrivateKey Equal error")

    // ======

    pub := &priv.PublicKey

    pubBytes := PublicKeyTo(pub)
    pub2, err := NewPublicKey(pubBytes)
    if err != nil {
        t.Fatal(err)
    }

    if !pub2.Equal(pub) {
        t.Error("NewPublicKey Equal error")
    }
}

func Test_Public(t *testing.T) {
    priv, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey
    pub2 := priv.Public()

    if !pub.Equal(pub2) {
        t.Error("Export Public Equal fail")
    }
}

func Test_Equal(t *testing.T) {
    priv, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    priv2, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub2 := &priv2.PublicKey

    if priv.Equal(priv2) {
        t.Error("PrivateKey should not Equal")
    }
    if pub.Equal(pub2) {
        t.Error("PublicKey should not Equal")
    }
}

func Test_SignVerify(t *testing.T) {
    priv, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    data := []byte("test-data test-data test-data test-data test-data")

    sig, err := priv.Sign(rand.Reader, data, nil)
    if err != nil {
        t.Fatal(err)
    }

    res := pub.Verify(data, sig)
    if !res {
        t.Error("Verify fail")
    }

}

func Test_SignVerify2(t *testing.T) {
    priv, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    data := []byte("test-data test-data test-data test-data test-data")

    sig, err := Sign(rand.Reader, priv, data)
    if err != nil {
        t.Fatal(err)
    }

    res, _ := Verify(pub, data, sig)
    if !res {
        t.Error("VerifyASN1 fail")
    }
}

func Test_Marshal(t *testing.T) {
    curve := e521.E521()

    priv, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    pubBytes := e521.Marshal(pub.Curve, pub.X, pub.Y)
    pubBytes2 := e521.MarshalCompressed(pub.Curve, pub.X, pub.Y)

    // t.Errorf("\n k: %x, \n p: %x \n", priv.D, pubBytes2)

    cryptobin_test.NotEmpty(t, pubBytes)
    cryptobin_test.NotEmpty(t, pubBytes2)

    x, y := elliptic.Unmarshal(curve, pubBytes)
    pub2 := &PublicKey{
        Curve: curve,
        X: x,
        Y: y,
    }

    x2, y2 := elliptic.UnmarshalCompressed(curve, pubBytes2)
    pub3 := &PublicKey{
        Curve: curve,
        X: x2,
        Y: y2,
    }

    cryptobin_test.Equal(t, pub, pub2)
    cryptobin_test.Equal(t, pub, pub3)
}

func Test_Vec_Check(t *testing.T) {
    for i, td := range testSigVec {
        t.Run(fmt.Sprintf("index %d", i), func(t *testing.T) {
            curve := e521.E521()

            if len(td.secretKey) > 0 {
                priv, err := NewPrivateKey(td.secretKey)
                if err != nil {
                    t.Fatal(err)
                }

                pub := &priv.PublicKey

                pubBytes := e521.MarshalCompressed(pub.Curve, pub.X, pub.Y)

                // check publicKey
                if !bytes.Equal(pubBytes, td.publicKey) {
                    t.Errorf("PublicKey got: %x, want: %x", pubBytes, td.publicKey)
                }

                // check sig
                sig, err := priv.Sign(rand.Reader, td.message, nil)
                if err != nil {
                    t.Error("encode sig fail")
                }

                if bytes.Equal(sig, td.signature) != td.verification {
                    t.Errorf("sig fail, got: %x, want: %x", sig, td.signature)
                }

            }

            x, y := e521.UnmarshalCompressed(curve, td.publicKey)
            if x == nil || y == nil {
                t.Fatal("publicKey error")
            }

            pubkey := &PublicKey{
                Curve: curve,
                X: x,
                Y: y,
            }

            veri := pubkey.Verify(td.message, td.signature)
            if veri != td.verification {
                t.Error("VerifyASN1 fail")
            }

        })
    }

}

type testVec struct {
    secretKey []byte
    publicKey []byte
    message   []byte
    signature []byte
    verification bool
}

var testSigVec = []testVec{
    {
        secretKey: fromHex("313e78bd2f5eb3f0a9ee0120496cb3c891a3d4f79d1b8c01f81cd7d70bcadefbb941a3058dabe6b5dbe559b6f5331cc0087af6a367d47555d5cb95a8dacea4d167"),
        publicKey: fromHex("8fa4530c005ec60d22cf5cea67b5059745acac5f20346b2cfefdce3d3f2ffa7687ed22c8bb7c758ccee7a98e834b0cf612cc70526d3d7e752887e2ce2f5de8a9ea01"),
        message:   fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        signature: fromHex("fe7941e471caa627fffcb566564acdf2c895099d9f674096dbdfd5a08f77a45d0866241ad2f62b248446b4b7edd62713689a0b3b973ebf4cb0947994d8183be154003f0cfb128a6741451926d1e4ab914606c1227293f9140b1cecdd345eddd370662e678e887414a6cc1df22fb7795c0ff16bbbace6f1ad895c01de85febaed73c80100"),
        verification: true,
    },

    // fail
    {
        secretKey: fromHex("22713dc2f3d8a4611e9266d8a2a9e3d237505dc34c65d87d598b9a4e6c41b35e3d090458e66c8213a4af011e5614377960c99d9f84e379fdd1f1e168b163b5d930"),
        publicKey: fromHex("1627c32ce2b21b1acad2786f92f1314ee673bb3569a9a8db7f9e7dd0072c54dfe42e6f49fd6321012c7c1e3155d8f7433329c1d5f12310200305683199091f647100"),
        message:   fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        signature: fromHex("fe7941e471caa627fffcb566564acdf2c895099d9f674096dbdfd5a08f77a45d0866241ad2f62b248446b4b7edd62713689a0b3b973ebf4cb0947994d8183be154003f0cfb128a6741451926d1e4ab914606c1227293f9140b1cecdd345eddd370662e678e887414a6cc1df22fb7795c0ff16bbbace6f1ad895c01de85febaed73c80100"),
        verification: false,
    },
}
