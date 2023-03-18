package encoding

import (
    "testing"
)

func Test_BinaryLittleEndian(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    data := uint16(61375)
    name := "BinaryLittleEndian"

    en := FromString("").BinaryLittleEndianEncode(data)
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    var deStr uint16
    de := FromString(enStr).BinaryLittleEndianDecode(&deStr)

    assertError(de.Error, name + " Decode error")

    assert(data, deStr, name)
}

func Test_BinaryBigEndian(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    data := uint16(61375)
    name := "BinaryBigEndian"

    en := FromString("").BinaryBigEndianEncode(data)
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    var deStr uint16
    de := FromString(enStr).BinaryBigEndianDecode(&deStr)

    assertError(de.Error, name + " Decode error")

    assert(data, deStr, name)
}

func Test_BinaryBigEndianBase64(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    data := uint16(61375)
    name := "BinaryBigEndianBase64"

    en := FromString("").BinaryBigEndianEncode(data).Base64Encode()
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    var deStr uint16
    de := FromString(enStr).Base64Decode().BinaryBigEndianDecode(&deStr)

    assertError(de.Error, name + " Decode error")

    assert(data, deStr, name)
}
