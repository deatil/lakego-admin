package encoding

import (
    "testing"
)

func Test_MorseITU(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    name := "MorseITU"
    data := "testpass"

    en := FromString(data).MorseITUEncode()
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    de := FromString(enStr).MorseITUDecode()
    deStr := de.ToString()

    assertError(de.Error, name + " Decode error")

    assert(data, deStr, name)
}
