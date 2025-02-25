package encoding

import (
    "testing"
)

func Test_Base36(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    name := "Base36"
    data := "test-pass"

    en := FromString(data).Base36Encode()
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    de := FromString(enStr).Base36Decode()
    deStr := de.ToString()

    assertError(de.Error, name + " Decode error")

    assert(data, deStr, name)
}
