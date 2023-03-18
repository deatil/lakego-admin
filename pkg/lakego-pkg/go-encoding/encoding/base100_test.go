package encoding

import (
    "testing"
)

func Test_Base100(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    name := "Base100"
    data := "test-pass"

    en := FromString(data).Base100Encode()
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    de := FromString(enStr).Base100Decode()
    deStr := de.ToString()

    assertError(de.Error, name + " Decode error")

    assert(data, deStr, name)
}
