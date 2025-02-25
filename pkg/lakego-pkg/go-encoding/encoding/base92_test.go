package encoding

import (
    "testing"
)

func Test_Base92(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    name := "Base92"
    data := "test-pass"

    en := FromString(data).Base92Encode()
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    de := FromString(enStr).Base92Decode()
    deStr := de.ToString()

    assertError(de.Error, name + " Decode error")

    assert(data, deStr, name)
}
