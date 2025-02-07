package wrap

import (
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

func Test_Name(t *testing.T) {
    eq := test.AssertEqualT(t)

    eq(Wrap.String(), "Wrap", "Test_Name")
}

// 输入数据需手动处理长度，不使用补码方式
func Test_AesWrap(t *testing.T) {
    assert := test.AssertEqualT(t)
    assertNoError := test.AssertNoErrorT(t)

    data := "kjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplo"
    cypt := crypto.FromString(data).
        SetKey("kkinjkijeel22plo").
        SetIv("dfertf12").
        Aes().
        ModeBy(Wrap).
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertNoError(cypt.Error(), "Test_AesWrap-Encode")

    cyptde := crypto.FromBase64String(cyptStr).
        SetKey("kkinjkijeel22plo").
        SetIv("dfertf12").
        Aes().
        ModeBy(Wrap).
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertNoError(cyptde.Error(), "Test_AesWrap-Decode")

    assert(data, cyptdeStr, "Test_AesWrap")
}

func Test_AesWrapWithNoIV(t *testing.T) {
    assert := test.AssertEqualT(t)
    assertNoError := test.AssertNoErrorT(t)

    data := "kjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplo"
    cypt := crypto.FromString(data).
        SetKey("kkinjkijeel22plo").
        WithIv(nil).
        Aes().
        ModeBy(Wrap).
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertNoError(cypt.Error(), "Test_AesWrapWithNoIV-Encode")

    cyptde := crypto.FromBase64String(cyptStr).
        SetKey("kkinjkijeel22plo").
        WithIv(nil).
        Aes().
        ModeBy(Wrap).
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertNoError(cyptde.Error(), "Test_AesWrapWithNoIV-Decode")

    assert(data, cyptdeStr, "Test_AesWrapWithNoIV")
}

func Test_AesWrap_Check(t *testing.T) {
    assert := test.AssertEqualT(t)
    assertNoError := test.AssertNoErrorT(t)

    /* aes key */
    var test_wrap_key = []byte{
        0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
        0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
        0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f,
    }

    /* Unique initialisation vector */
    var test_wrap_iv = []byte{
        0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84,
        0x99, 0xaa, 0x3e, 0x68,
    }

    /* Example plaintext to encrypt */
    var test_wrap_pt = []byte{
        0xad, 0x4f, 0xc9, 0xfc, 0x77, 0x69, 0xc9, 0xea, 0xfc, 0xdf, 0x00, 0xac,
        0x34, 0xec, 0x40, 0xbc, 0x28, 0x3f, 0xa4, 0x5e, 0xd8, 0x99, 0xe4, 0x5d,
        0x5e, 0x7a, 0xc4, 0xe6, 0xca, 0x7b, 0xa5, 0xb7,
    }

    /* Expected ciphertext value */
    var test_wrap_ct = []byte{
        0x97, 0x99, 0x55, 0xca, 0xf6, 0x3e, 0x95, 0x54, 0x39, 0xd6, 0xaf, 0x63, 0xff, 0x2c, 0xe3, 0x96,
        0xf7, 0x0d, 0x2c, 0x9c, 0xc7, 0x43, 0xc0, 0xb6, 0x31, 0x43, 0xb9, 0x20, 0xac, 0x6b, 0xd3, 0x67,
        0xad, 0x01, 0xaf, 0xa7, 0x32, 0x74, 0x26, 0x92,
    }

    cypt := crypto.FromBytes(test_wrap_pt).
        WithKey(test_wrap_key).
        WithIv(test_wrap_iv).
        Aes().
        ModeBy(Wrap).
        Encrypt()
    cyptStr := cypt.ToBytes()

    assertNoError(cypt.Error(), "Test_AesWrap_Check-Encode")
    assert(cyptStr, test_wrap_ct, "Test_AesWrap_Check")
}
