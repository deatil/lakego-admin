package lms

import (
    "testing"
    "crypto"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/tool/test"
)

func Test_HSS_SignerInterface(t *testing.T) {
    var _ crypto.Signer = &HSSPrivateKey{}
}

func test_HSS_SignVerify(t *testing.T, opts []HSSOpts) {
    assertBool := test.AssertBoolT(t)

    priv, err := GenerateHSSKey(rand.Reader, opts)
    if err != nil {
        panic(err)
    }

    pub := priv.HSSPublicKey

    sig, err := priv.Sign(rand.Reader, []byte("example"), nil)
    if err != nil {
        panic(err)
    }

    result := pub.Verify([]byte("example"), sig)
    assertBool(result, "HSSSignVerify")
}

func Test_HSS_SignVerify(t *testing.T) {
    t.Run("DefaultOpts", func(t *testing.T) {
        test_HSS_SignVerify(t, DefaultOpts)
    })
    t.Run("Opts 1", func(t *testing.T) {
        test_HSS_SignVerify(t, []HSSOpts{
            HSSOpts{
                Type:    LMS_SHA256_M32_H5,
                OtsType: LMOTS_SHA256_N32_W8,
            },
        })
    })
    t.Run("Opts 2", func(t *testing.T) {
        test_HSS_SignVerify(t, []HSSOpts{
            HSSOpts{
                Type:    LMS_SHA256_M32_H5,
                OtsType: LMOTS_SHA256_N32_W8,
            },
            HSSOpts{
                Type:    LMS_SHA256_M32_H5,
                OtsType: LMOTS_SHA256_N32_W8,
            },
        })
    })
    t.Run("Opts 3", func(t *testing.T) {
        test_HSS_SignVerify(t, []HSSOpts{
            HSSOpts{
                Type:    LMS_SHA256_M32_H5,
                OtsType: LMOTS_SHA256_N32_W8,
            },
            HSSOpts{
                Type:    LMS_SHA256_M32_H5,
                OtsType: LMOTS_SHA256_N32_W8,
            },
            HSSOpts{
                Type:    LMS_SHA256_M32_H5,
                OtsType: LMOTS_SHA256_N32_W8,
            },
        })
    })
    t.Run("Opts 4", func(t *testing.T) {
        test_HSS_SignVerify(t, []HSSOpts{
            HSSOpts{
                Type:    LMS_SHA256_M32_H5,
                OtsType: LMOTS_SHA256_N32_W8,
            },
            HSSOpts{
                Type:    LMS_SHA256_M32_H5,
                OtsType: LMOTS_SHA256_N32_W8,
            },
            HSSOpts{
                Type:    LMS_SHA256_M32_H5,
                OtsType: LMOTS_SHA256_N32_W8,
            },
            HSSOpts{
                Type:    LMS_SHA256_M32_H5,
                OtsType: LMOTS_SHA256_N32_W8,
            },
        })
    })
    t.Run("Opts 5", func(t *testing.T) {
        test_HSS_SignVerify(t, []HSSOpts{
            HSSOpts{
                Type:    LMS_SHA256_M32_H5,
                OtsType: LMOTS_SHA256_N32_W8,
            },
            HSSOpts{
                Type:    LMS_SHA256_M32_H5,
                OtsType: LMOTS_SHA256_N32_W8,
            },
            HSSOpts{
                Type:    LMS_SHA256_M32_H5,
                OtsType: LMOTS_SHA256_N32_W8,
            },
            HSSOpts{
                Type:    LMS_SHA256_M32_H5,
                OtsType: LMOTS_SHA256_N32_W8,
            },
            HSSOpts{
                Type:    LMS_SHA256_M32_H5,
                OtsType: LMOTS_SHA256_N32_W8,
            },
        })
    })

}

func Test_HSS_PublicKey_ToBytes(t *testing.T) {
    assertEqual := test.AssertEqualT(t)
    assertNotEmpty := test.AssertNotEmptyT(t)

    priv, err := GenerateHSSKey(rand.Reader, DefaultOpts)
    if err != nil {
        panic(err)
    }

    pub := priv.HSSPublicKey

    pubBytes := pub.ToBytes()
    assertNotEmpty(pubBytes, "pub.ToBytes")

    pub2, err := NewHSSPublicKeyFromBytes(pubBytes)
    if err != nil {
        panic(err)
    }

    assertEqual(pub2.Levels, pub.Levels, "pub.Levels")
    assertEqual(pub2.LmsPub.ToBytes(), pub.LmsPub.ToBytes(), "pub.LmsPub.ToBytes")
}

func Test_HSS_PrivateKey_ToBytes(t *testing.T) {
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

func Test_HSS_Equal(t *testing.T) {
    assertBool := test.AssertBoolT(t)
    assertNotBool := test.AssertNotBoolT(t)

    t.Run("good", func(t *testing.T) {
        priv, err := GenerateHSSKey(rand.Reader, DefaultOpts)
        if err != nil {
            panic(err)
        }

        pub := priv.HSSPublicKey

        priv2 := priv
        pub2 := pub

        assertBool(priv2.Equal(priv), "HSSPrivateKey")
        assertBool(pub2.Equal(&pub), "HSSPublicKey")

        // =========

        privBytes, _ := priv.ToBytes()
        pubBytes := pub.ToBytes()

        priv3, _ := NewHSSPrivateKeyFromBytes(privBytes)
        pub3, _ := NewHSSPublicKeyFromBytes(pubBytes)

        assertBool(priv3.Equal(priv), "PrivateKey Bytes")
        assertBool(pub3.Equal(&pub), "PublicKey Bytes")
    })

    t.Run("bad", func(t *testing.T) {
        priv, err := GenerateHSSKey(rand.Reader, DefaultOpts)
        if err != nil {
            panic(err)
        }

        pub := priv.HSSPublicKey

        // ===========

        priv2, err := GenerateHSSKey(rand.Reader, DefaultOpts)
        if err != nil {
            panic(err)
        }

        pub2 := priv2.HSSPublicKey

        assertNotBool(priv2.Equal(priv), "HSSPrivateKey")
        assertNotBool(pub2.Equal(&pub), "HSSPublicKey")
    })
}
