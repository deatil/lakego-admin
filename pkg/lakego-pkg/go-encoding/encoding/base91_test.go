package encoding

import (
    "testing"
)

func Test_Base91(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    name := "Base91"
    data := "test-pass"

    en := FromString(data).Base91Encode()
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    de := FromString(enStr).Base91Decode()
    deStr := de.ToString()

    assertError(de.Error, name + " Decode error")

    assert(data, deStr, name)
}
