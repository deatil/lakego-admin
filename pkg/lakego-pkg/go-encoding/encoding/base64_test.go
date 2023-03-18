package encoding

import (
    "testing"
)

func Test_Base64(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    data := "test-pass"

    en := FromString(data).Base64Encode()
    enStr := en.ToString()

    assertError(en.Error, "Base64 Encode error")

    de := FromString(enStr).Base64Decode()
    deStr := de.ToString()

    assertError(de.Error, "Base64 Decode error")

    assert(data, deStr, "Base64")
}

func Test_Base64URL(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    data := "test-pass"

    en := FromString(data).Base64URLEncode()
    enStr := en.ToString()

    assertError(en.Error, "Base64URL Encode error")

    de := FromString(enStr).Base64URLDecode()
    deStr := de.ToString()

    assertError(de.Error, "Base64URL Decode error")

    assert(data, deStr, "Base64URL")
}

func Test_Base64Raw(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    data := "test-pass"

    en := FromString(data).Base64RawEncode()
    enStr := en.ToString()

    assertError(en.Error, "Base64Raw Encode error")

    de := FromString(enStr).Base64RawDecode()
    deStr := de.ToString()

    assertError(de.Error, "Base64Raw Decode error")

    assert(data, deStr, "Base64Raw")
}

func Test_Base64RawURL(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    data := "test-pass"

    en := FromString(data).Base64RawURLEncode()
    enStr := en.ToString()

    assertError(en.Error, "Base64RawURL Encode error")

    de := FromString(enStr).Base64RawURLDecode()
    deStr := de.ToString()

    assertError(de.Error, "Base64RawURL Decode error")

    assert(data, deStr, "Base64RawURL")
}

func Test_Base64Segment(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    data := "test-pass"

    en := FromString(data).Base64SegmentEncode()
    enStr := en.ToString()

    assertError(en.Error, "Base64Segment Encode error")

    de := FromString(enStr).Base64SegmentDecode()
    deStr := de.ToString()

    assertError(de.Error, "Base64Segment Decode error")

    assert(data, deStr, "Base64Segment")
}

func Test_Base64Encoder(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    data := "test-pass"
    const encodeTest = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789;/"

    en := FromString(data).Base64EncodeWithEncoder(encodeTest)
    enStr := en.ToString()

    assertError(en.Error, "Base64Encoder Encode error")

    de := FromString(enStr).Base64DecodeWithEncoder(encodeTest)
    deStr := de.ToString()

    assertError(de.Error, "Base64Encoder Decode error")

    assert(data, deStr, "Base64Encoder")
}

