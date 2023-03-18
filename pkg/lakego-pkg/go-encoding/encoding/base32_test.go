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
