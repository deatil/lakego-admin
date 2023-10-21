package encoding

import (
    "testing"
)

func Test_Base32(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    name := "Base32"
    data := "test-pass"

    en := FromString(data).Base32Encode()
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    de := FromString(enStr).Base32Decode()
    deStr := de.ToString()

    assertError(de.Error, name + " Decode error")

    assert(data, deStr, name)
}

func Test_Base32Raw(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    name := "Base32"
    data := "test-pass"

    en := FromString(data).Base32RawEncode()
    enStr := en.ToString()

    assertError(en.Error, name + "Base32Raw- Encode error")

    de := FromString(enStr).Base32RawDecode()
    deStr := de.ToString()

    assertError(de.Error, name + "Base32Raw- Decode error")

    assert(data, deStr, name)
}

func Test_Base32Hex(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    name := "Base32Hex"
    data := "test-pass"

    en := FromString(data).Base32HexEncode()
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    de := FromString(enStr).Base32HexDecode()
    deStr := de.ToString()

    assertError(de.Error, name + " Decode error")

    assert(data, deStr, name)
}

func Test_Base32RawHex(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    name := "Base32Hex"
    data := "test-pass"

    en := FromString(data).Base32RawHexEncode()
    enStr := en.ToString()

    assertError(en.Error, name + "Base32RawHex- Encode error")

    de := FromString(enStr).Base32RawHexDecode()
    deStr := de.ToString()

    assertError(de.Error, name + "Base32RawHex- Decode error")

    assert(data, deStr, name)
}

func Test_Base32Encoder(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    name := "Base32Encoder"
    data := "test-pass"

    const encodeTest = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234569"

    en := FromString(data).Base32EncodeWithEncoder(encodeTest)
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    de := FromString(enStr).Base32DecodeWithEncoder(encodeTest)
    deStr := de.ToString()

    assertError(de.Error, name + " Decode error")

    assert(data, deStr, name)
}

func Test_Base32RawEncoder(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    name := "Base32Encoder"
    data := "test-pass"

    const encodeTest = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234569"

    en := FromString(data).Base32RawEncodeWithEncoder(encodeTest)
    enStr := en.ToString()

    assertError(en.Error, name + "Base32RawEncoder- Encode error")

    de := FromString(enStr).Base32RawDecodeWithEncoder(encodeTest)
    deStr := de.ToString()

    assertError(de.Error, name + "Base32RawEncoder- Decode error")

    assert(data, deStr, name)
}
