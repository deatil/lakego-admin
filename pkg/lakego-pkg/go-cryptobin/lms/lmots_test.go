package lms

import (
    "testing"
    "crypto/rand"
    "encoding/hex"

    "github.com/deatil/go-cryptobin/tool/test"
)

func test_OtsSignVerify(t *testing.T, otstc ILmotsParam) {
    assertBool := test.AssertBoolT(t)

    var err error

    id, err := hex.DecodeString("d08fabd4a2091ff0a8cb4ed834e74534")
    if err != nil {
        panic(err)
    }

    ots_priv, err := NewLmsOtsPrivateKey(otstc, 0, ID(id))
    if err != nil {
        panic(err)
    }

    ots_pub := ots_priv.Public()

    ots_sig, err := ots_priv.Sign(rand.Reader, []byte("example"))
    if err != nil {
        panic(err)
    }

    result := ots_pub.Verify([]byte("example"), ots_sig)
    assertBool(result, "OtsSignVerify")
}

func Test_OtsSignVerify(t *testing.T) {
    t.Run("OtsSignVerify_W1", func(t *testing.T) {
        test_OtsSignVerify(t, LMOTS_SHA256_N32_W1_Param)
    })
    t.Run("OtsSignVerify_W2", func(t *testing.T) {
        test_OtsSignVerify(t, LMOTS_SHA256_N32_W2_Param)
    })
    t.Run("OtsSignVerify_W4", func(t *testing.T) {
        test_OtsSignVerify(t, LMOTS_SHA256_N32_W4_Param)
    })
    t.Run("OtsSignVerify_W8", func(t *testing.T) {
        test_OtsSignVerify(t, LMOTS_SHA256_N32_W8_Param)
    })

    t.Run("OtsSignVerify_SM3_W1", func(t *testing.T) {
        test_OtsSignVerify(t, LMOTS_SM3_N32_W1_Param)
    })
    t.Run("OtsSignVerify_SM3_W2", func(t *testing.T) {
        test_OtsSignVerify(t, LMOTS_SM3_N32_W2_Param)
    })
    t.Run("OtsSignVerify_SM3_W4", func(t *testing.T) {
        test_OtsSignVerify(t, LMOTS_SM3_N32_W4_Param)
    })
    t.Run("OtsSignVerify_SM3_W8", func(t *testing.T) {
        test_OtsSignVerify(t, LMOTS_SM3_N32_W8_W8_Param)
    })
}

func test_OtsSignVerifyFail(t *testing.T, otstc ILmotsParam) {
    assertNotBool := test.AssertNotBoolT(t)

    var err error

    id, err := hex.DecodeString("d08fabd4a2091ff0a8cb4ed834e74534")
    if err != nil {
        panic(err)
    }

    ots_priv, err := NewLmsOtsPrivateKey(otstc, 0, ID(id))
    if err != nil {
        panic(err)
    }

    ots_pub := ots_priv.Public()

    ots_sig, err := ots_priv.Sign(rand.Reader, []byte("example"))
    if err != nil {
        panic(err)
    }

    // modify q so that the verification fails
    ots_pub_bytes := ots_pub.ToBytes()
    ots_pub_bytes[23] = 6
    ots_pub, err = NewLmsOtsPublicKeyFromBytes(ots_pub_bytes)
    if err != nil {
        panic(err)
    }

    result := ots_pub.Verify([]byte("example"), ots_sig)
    assertNotBool(result, "OtsSignVerifyFail")
}

func Test_OtsSignVerifyFail(t *testing.T) {
    t.Run("OtsSignVerifyFail_W1", func(t *testing.T) {
        test_OtsSignVerifyFail(t, LMOTS_SHA256_N32_W1_Param)
    })
    t.Run("OtsSignVerifyFail_W2", func(t *testing.T) {
        test_OtsSignVerifyFail(t, LMOTS_SHA256_N32_W2_Param)
    })
    t.Run("OtsSignVerifyFail_W4", func(t *testing.T) {
        test_OtsSignVerifyFail(t, LMOTS_SHA256_N32_W4_Param)
    })
    t.Run("OtsSignVerifyFail_W8", func(t *testing.T) {
        test_OtsSignVerifyFail(t, LMOTS_SHA256_N32_W8_Param)
    })
}

func Test_DoubleSign(t *testing.T) {
    assertError := test.AssertErrorT(t)
    assertNotErrorNil := test.AssertNotErrorNilT(t)

    var err error

    id, err := hex.DecodeString("d08fabd4a2091ff0a8cb4ed834e74534")
    assertError(err, "hex.DecodeString")

    ots_priv, err := NewLmsOtsPrivateKey(LMOTS_SHA256_N32_W1_Param, 0, ID(id))
    assertError(err, "NewLmsOtsPrivateKey")

    _, err = ots_priv.Sign(rand.Reader, []byte("example"))
    assertError(err, "priv.Sign")

    _, err = ots_priv.Sign(rand.Reader, []byte("example2"))
    assertNotErrorNil(err, "priv.Sign 2")
}
