package encoding

import (
    "testing"
)

func Test_Hex(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    name := "Hex"
    data := "test-pass"

    en := FromString(data).HexEncode()
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    de := FromString(enStr).HexDecode()
    deStr := de.ToString()

    assertError(de.Error, name + " Decode error")

    assert(data, deStr, name)
}
