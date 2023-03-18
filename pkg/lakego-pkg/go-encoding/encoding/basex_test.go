package encoding

import (
    "testing"
)

func Test_Basex2(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    name := "Basex2"
    data := "test-pass"

    en := FromString(data).Basex2Encode()
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    de := FromString(enStr).Basex2Decode()
    deStr := de.ToString()

    assertError(de.Error, name + " Decode error")

    assert(data, deStr, name)
}

func Test_Basex16(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    name := "Basex16"
    data := "test-pass"

    en := FromString(data).Basex16Encode()
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    de := FromString(enStr).Basex16Decode()
    deStr := de.ToString()

    assertError(de.Error, name + " Decode error")

    assert(data, deStr, name)
}

func Test_Basex62(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    name := "Basex62"
    data := "test-pass"

    en := FromString(data).Basex62Encode()
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    de := FromString(enStr).Basex62Decode()
    deStr := de.ToString()

    assertError(de.Error, name + " Decode error")

    assert(data, deStr, name)
}

func Test_BasexEncoder(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    name := "Base32Encoder"
    data := "test-pass"

    const encodeTest = "ACDEFGHIJKLMNOPQRSTUVWXYZ234569"

    en := FromString(data).BasexEncodeWithEncoder(encodeTest)
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    de := FromString(enStr).BasexDecodeWithEncoder(encodeTest)
    deStr := de.ToString()

    assertError(de.Error, name + " Decode error")

    assert(data, deStr, name)
}
