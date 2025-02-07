package lms

import (
    "testing"
    "crypto"
    "crypto/rand"
    "encoding/hex"

    "github.com/deatil/go-cryptobin/tool/test"
)

func Test_Ots_Interface(t *testing.T) {
    var _ crypto.Signer = &LmotsPrivateKey{}
    var _ crypto.SignerOpts = LmotsSignerOpts{}
}

func test_OtsSignVerify(t *testing.T, otstc ILmotsParam) {
    assertTrue := test.AssertTrueT(t)

    var err error

    id, err := hex.DecodeString("d08fabd4a2091ff0a8cb4ed834e74534")
    if err != nil {
        panic(err)
    }

    ots_priv, err := NewLmotsPrivateKey(otstc, 0, ID(id))
    if err != nil {
        panic(err)
    }

    ots_pub := ots_priv.LmotsPublicKey

    ots_sig, err := ots_priv.Sign(rand.Reader, []byte("example"), nil)
    if err != nil {
        panic(err)
    }

    result := ots_pub.Verify([]byte("example"), ots_sig)
    assertTrue(result, "OtsSignVerify")
}

func Test_OtsSignVerify(t *testing.T) {
    t.Run("OtsSignVerify_W1", func(t *testing.T) {
        test_OtsSignVerify(t, LMOTS_SHA256_N32_W1)
    })
    t.Run("OtsSignVerify_W2", func(t *testing.T) {
        test_OtsSignVerify(t, LMOTS_SHA256_N32_W2)
    })
    t.Run("OtsSignVerify_W4", func(t *testing.T) {
        test_OtsSignVerify(t, LMOTS_SHA256_N32_W4)
    })
    t.Run("OtsSignVerify_W8", func(t *testing.T) {
        test_OtsSignVerify(t, LMOTS_SHA256_N32_W8)
    })

    t.Run("OtsSignVerify_SM3_W1", func(t *testing.T) {
        test_OtsSignVerify(t, LMOTS_SM3_N32_W1)
    })
    t.Run("OtsSignVerify_SM3_W2", func(t *testing.T) {
        test_OtsSignVerify(t, LMOTS_SM3_N32_W2)
    })
    t.Run("OtsSignVerify_SM3_W4", func(t *testing.T) {
        test_OtsSignVerify(t, LMOTS_SM3_N32_W4)
    })
    t.Run("OtsSignVerify_SM3_W8", func(t *testing.T) {
        test_OtsSignVerify(t, LMOTS_SM3_N32_W8)
    })
}

func test_OtsSignVerifyFail(t *testing.T, otstc ILmotsParam) {
    assertFalse := test.AssertFalseT(t)

    var err error

    id, err := hex.DecodeString("d08fabd4a2091ff0a8cb4ed834e74534")
    if err != nil {
        panic(err)
    }

    ots_priv, err := NewLmotsPrivateKey(otstc, 0, ID(id))
    if err != nil {
        panic(err)
    }

    ots_pub := ots_priv.LmotsPublicKey

    ots_sig, err := ots_priv.Sign(rand.Reader, []byte("example"), nil)
    if err != nil {
        panic(err)
    }

    // modify q so that the verification fails
    ots_pub_bytes := ots_pub.ToBytes()
    ots_pub_bytes[23] = 6
    ots_pub2, err := NewLmotsPublicKeyFromBytes(ots_pub_bytes)
    if err != nil {
        panic(err)
    }

    result := ots_pub2.Verify([]byte("example"), ots_sig)
    assertFalse(result, "OtsSignVerifyFail")
}

func Test_OtsSignVerifyFail(t *testing.T) {
    t.Run("OtsSignVerifyFail_W1", func(t *testing.T) {
        test_OtsSignVerifyFail(t, LMOTS_SHA256_N32_W1)
    })
    t.Run("OtsSignVerifyFail_W2", func(t *testing.T) {
        test_OtsSignVerifyFail(t, LMOTS_SHA256_N32_W2)
    })
    t.Run("OtsSignVerifyFail_W4", func(t *testing.T) {
        test_OtsSignVerifyFail(t, LMOTS_SHA256_N32_W4)
    })
    t.Run("OtsSignVerifyFail_W8", func(t *testing.T) {
        test_OtsSignVerifyFail(t, LMOTS_SHA256_N32_W8)
    })
}

func Test_DoubleSign(t *testing.T) {
    assertNoError := test.AssertNoErrorT(t)
    assertError := test.AssertErrorT(t)

    var err error

    id, err := hex.DecodeString("d08fabd4a2091ff0a8cb4ed834e74534")
    assertNoError(err, "hex.DecodeString")

    ots_priv, err := NewLmotsPrivateKey(LMOTS_SHA256_N32_W1, 0, ID(id))
    assertNoError(err, "NewLmotsPrivateKey")

    _, err = ots_priv.Sign(rand.Reader, []byte("example"), nil)
    assertNoError(err, "priv.Sign")

    _, err = ots_priv.Sign(rand.Reader, []byte("example2"), nil)
    assertError(err, "priv.Sign 2")
}

func Test_OTS_ParamName(t *testing.T) {
    assertEqual := test.AssertEqualT(t)

    assertEqual(LMOTS_SHA256_N32_W1.String(), "LMOTS_SHA256_N32_W1", "")
    assertEqual(LMOTS_SHA256_N32_W2.String(), "LMOTS_SHA256_N32_W2", "")
    assertEqual(LMOTS_SHA256_N32_W4.String(), "LMOTS_SHA256_N32_W4", "")
    assertEqual(LMOTS_SHA256_N32_W8.String(), "LMOTS_SHA256_N32_W8", "")

    assertEqual(LMOTS_SM3_N32_W1.String(), "LMOTS_SM3_N32_W1", "")
    assertEqual(LMOTS_SM3_N32_W2.String(), "LMOTS_SM3_N32_W2", "")
    assertEqual(LMOTS_SM3_N32_W4.String(), "LMOTS_SM3_N32_W4", "")
    assertEqual(LMOTS_SM3_N32_W8.String(), "LMOTS_SM3_N32_W8", "")
}

func Test_Ots_Equal(t *testing.T) {
    assertTrue := test.AssertTrueT(t)
    assertFalse := test.AssertFalseT(t)

    t.Run("good", func(t *testing.T) {
        id, err := hex.DecodeString("d08fabd4a2091ff0a8cb4ed834e74534")
        if err != nil {
            panic(err)
        }

        ots_priv, err := NewLmotsPrivateKey(LMOTS_SHA256_N32_W1, 0, ID(id))
        if err != nil {
            panic(err)
        }

        ots_pub := ots_priv.LmotsPublicKey

        ots_priv2 := ots_priv
        ots_pub2 := ots_pub

        assertTrue(ots_priv2.Equal(ots_priv), "LmotsPrivateKey")
        assertTrue(ots_pub2.Equal(&ots_pub), "LmotsPublicKey")
    })

    t.Run("bad", func(t *testing.T) {
        id, err := hex.DecodeString("d08fabd4a2091ff0a8cb4ed834e74534")
        if err != nil {
            panic(err)
        }

        ots_priv, err := NewLmotsPrivateKey(LMOTS_SHA256_N32_W1, 0, ID(id))
        if err != nil {
            panic(err)
        }

        ots_pub := ots_priv.LmotsPublicKey

        // ===========

        id2, err := hex.DecodeString("d58fabd4a2091ff0a8cb4ed834e74534")
        if err != nil {
            panic(err)
        }

        ots_priv2, err := NewLmotsPrivateKey(LMOTS_SHA256_N32_W1, 0, ID(id2))
        if err != nil {
            panic(err)
        }

        ots_pub2 := ots_priv2.LmotsPublicKey

        assertFalse(ots_priv2.Equal(ots_priv), "LmotsPrivateKey")
        assertFalse(ots_pub2.Equal(&ots_pub), "LmotsPublicKey")
    })
}
