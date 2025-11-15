package kg

import (
    "fmt"
    "bytes"
    "testing"
    "math/big"
    "crypto"
    "crypto/rand"
    "crypto/sha256"
    "crypto/elliptic"
    "encoding/pem"
    "encoding/hex"

    "github.com/deatil/go-cryptobin/elliptic/kg"
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
    var _ crypto.Signer     = (*PrivateKey)(nil)
    var _ crypto.SignerOpts = (*SignerOpts)(nil)
}

func Test_SignerInterface(t *testing.T) {
    priv, err := GenerateKey(rand.Reader, kg.KG256r1())
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    var _ crypto.Signer = priv
    var _ crypto.PublicKey = pub
}

func Test_NewPrivateKey(t *testing.T) {
    p256 := kg.KG256r1()

    priv, err := GenerateKey(rand.Reader, p256)
    if err != nil {
        t.Fatal(err)
    }

    privBytes := PrivateKeyTo(priv)
    priv2, err := NewPrivateKey(p256, privBytes)
    if err != nil {
        t.Fatal(err)
    }

    if !priv2.Equal(priv) {
        t.Error("NewPrivateKey Equal error")
    }

    // ======

    pub := &priv.PublicKey

    pubBytes := PublicKeyTo(pub)
    pub2, err := NewPublicKey(p256, pubBytes)
    if err != nil {
        t.Fatal(err)
    }

    if !pub2.Equal(pub) {
        t.Error("NewPublicKey Equal error")
    }
}

func Test_Public(t *testing.T) {
    priv, err := GenerateKey(rand.Reader, kg.KG256r1())
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
    priv, err := GenerateKey(rand.Reader, kg.KG256r1())
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    priv2, err := GenerateKey(rand.Reader, kg.KG256r1())
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
    priv, err := GenerateKey(rand.Reader, kg.KG256r1())
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    data := []byte("test-data test-data test-data test-data test-data")

    sig, err := SignASN1(rand.Reader, priv, sha256.New, data)
    if err != nil {
        t.Fatal(err)
    }

    res, _ := VerifyASN1(pub, sha256.New, data, sig)
    if !res {
        t.Error("VerifyASN1 fail")
    }

}

func Test_SignVerify1(t *testing.T) {
    priv, err := GenerateKey(rand.Reader, kg.KG384r1())
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    data := []byte("test-data test-data test-data test-data test-data")

    sig, err := SignASN1(rand.Reader, priv, sha256.New, data)
    if err != nil {
        t.Fatal(err)
    }

    res, _ := VerifyASN1(pub, sha256.New, data, sig)
    if !res {
        t.Error("VerifyASN1 fail")
    }

}

func Test_SignVerify2(t *testing.T) {
    priv, err := GenerateKey(rand.Reader, kg.KG256r1())
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

    res := pub.Verify(data, sig, &SignerOpts{
        Hash: sha256.New,
    })
    if !res {
        t.Error("Verify fail")
    }

}

func Test_ECDH(t *testing.T) {
    priv, err := GenerateKey(rand.Reader, kg.KG256r1())
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    priv2, err := GenerateKey(rand.Reader, kg.KG256r1())
    if err != nil {
        t.Fatal(err)
    }

    pub2 := &priv2.PublicKey

    priv3, err := GenerateKey(rand.Reader, kg.KG256r1())
    if err != nil {
        t.Fatal(err)
    }

    secret1, err := priv.ECDH(pub2)
    if err != nil {
        t.Fatal(err)
    }

    secret2, err := priv2.ECDH(pub)
    if err != nil {
        t.Fatal(err)
    }

    secret3, err := priv3.ECDH(pub)
    if err != nil {
        t.Fatal(err)
    }

    cryptobin_test.Equal(t, secret2, secret1, "ECDH equal")
    cryptobin_test.NotEqual(t, secret3, secret2, "ECDH not equal")
}

func Test_Marshal(t *testing.T) {
    curve := kg.KG256r1()

    priv, err := GenerateKey(rand.Reader, curve)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    pubBytes := kg.Marshal(pub.Curve, pub.X, pub.Y)
    pubBytes2 := kg.MarshalCompressed(pub.Curve, pub.X, pub.Y)

    // t.Errorf("\n k: %x, \n p: %x \n", priv.D, pubBytes2)
    // t.Errorf("\n x: %x, \n y: %x \n", pub.X, pub.Y)

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

func Test_Marshal2(t *testing.T) {
    curve := kg.KG384r1()

    priv, err := GenerateKey(rand.Reader, curve)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    pubBytes := kg.Marshal(pub.Curve, pub.X, pub.Y)
    pubBytes2 := kg.MarshalCompressed(pub.Curve, pub.X, pub.Y)

    // t.Errorf("\n k: %x, \n p: %x \n", priv.D, pubBytes2)
    // t.Errorf("\n x: %x, \n y: %x \n", pub.X, pub.Y)

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
            curve := kg.KG256r1()

            if len(td.secretKey) > 0 {
                priv, err := NewPrivateKey(curve, td.secretKey)
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
                sig, err := encodeSignature(r, s)
                if err != nil {
                    t.Error("encode sig fail")
                }

                if bytes.Equal(sig, td.signature) != td.verification {
                    t.Errorf("sig fail, got: %x, want: %x", sig, td.signature)
                }

            }

            pubBytes := append([]byte{byte(3)}, td.publicKey...)

            x, y := elliptic.UnmarshalCompressed(curve, pubBytes)
            if x == nil || y == nil {
                t.Fatal("publicKey error")
            }

            pubkey := &PublicKey{
                Curve: curve,
                X: x,
                Y: y,
            }

            veri, _ := VerifyASN1(pubkey, sha256.New, td.message, td.signature)
            if veri != td.verification {
                t.Error("VerifyASN1 fail")
            }

        })
    }

}

// sha256, KG256r1
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
        secretKey: fromHex("47A50FB8BB7E77CD4EA275196DAEBFF3C104B34668B950EE6D1E2A569A473940"),
        publicKey: fromHex("6FD88E06683F486F67E13A62B7C6E4848042B465100F9C916CD42B85DD8AEFA5"),
        auxRand:   fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        message:   fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        signature: fromHex("3046022100AA054D043604B77933DE1C1E2905E99EB081E163C43CA7B323CDEFE00D2049750221009C264BDE65B8E5761CB475A9311749C0397081C71D4F2822A6A3F050D8272D6C"),
        verification: true,
    },

    // fail
    {
        secretKey: fromHex("47A50FB8BB7E77CD4EA275196DAEBFF3C104B34668B950EE6D1E2A569A473940"),
        publicKey: fromHex("6FD88E06683F486F67E13A62B7C6E4848042B465100F9C916CD42B85DD8AEFA5"),
        auxRand:   fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        message:   fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        signature: fromHex("3246022100AA054D043604B77933DE1C1E2905E99EB081E163C43CA7B323CDEFE00D2049750221009C264BDE65B8E5761CB475A9311749C0397081C71D4F2822A6A3F050D8272D6C"),
        verification: false,
    },
}
