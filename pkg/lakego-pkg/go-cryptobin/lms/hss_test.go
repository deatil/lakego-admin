package lms

import (
    "testing"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/tool/test"
)

func Test_HSSSignVerify(t *testing.T) {
    assertBool := test.AssertBoolT(t)

    priv, err := GenerateHSSKey(rand.Reader, DefaultOpts)
    if err != nil {
        panic(err)
    }

    pub := priv.Public()

    sig, err := priv.Sign(rand.Reader, []byte("example"))
    if err != nil {
        panic(err)
    }

    result := pub.Verify([]byte("example"), sig)
    assertBool(result, "HSSSignVerify")
}

func Test_HSSPublicKey_ToBytes(t *testing.T) {
    assertEqual := test.AssertEqualT(t)
    assertNotEmpty := test.AssertNotEmptyT(t)

    priv, err := GenerateHSSKey(rand.Reader, DefaultOpts)
    if err != nil {
        panic(err)
    }

    pub := priv.Public()

    pubBytes := pub.ToBytes()
    assertNotEmpty(pubBytes, "pub.ToBytes")

    pub2, err := NewHSSPublicKeyFromBytes(pubBytes)
    if err != nil {
        panic(err)
    }

    assertEqual(pub2.Levels, pub.Levels, "pub.Levels")
    assertEqual(pub2.LmsPub.ToBytes(), pub.LmsPub.ToBytes(), "pub.LmsPub.ToBytes")
}

func Test_HSSPrivateKey_ToBytes(t *testing.T) {
    assertEqual := test.AssertEqualT(t)
    assertNotEmpty := test.AssertNotEmptyT(t)

    priv, err := GenerateHSSKey(rand.Reader, DefaultOpts)
    if err != nil {
        panic(err)
    }

    privBytes, err := priv.ToBytes()
    if err != nil {
        panic(err)
    }

    assertNotEmpty(privBytes, "priv.ToBytes")

    priv2, err := NewHSSPrivateKeyFromBytes(privBytes)
    if err != nil {
        panic(err)
    }

    assertEqual(priv2.Levels, priv.Levels, "priv.Levels")
    assertEqual(priv2.HSSPublicKey.LmsPub.ToBytes(), priv.HSSPublicKey.LmsPub.ToBytes(), "priv.LmsPub.ToBytes")

    assertEqual(len(priv2.LmsKey), 5, "priv.LmsKey len")
    assertEqual(priv2.LmsKey[0].ToBytes(), priv.LmsKey[0].ToBytes(), "priv.LmsKey[0].ToBytes")
    assertEqual(priv2.LmsKey[1].ToBytes(), priv.LmsKey[1].ToBytes(), "priv.LmsKey[1].ToBytes")

    sig0_2, _ := priv2.LmsSig[0].ToBytes()
    sig0, _ := priv.LmsSig[0].ToBytes()
    assertEqual(sig0_2, sig0, "priv.LmsSig[0].ToBytes")
}
