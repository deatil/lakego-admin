package encoding

import (
    "testing"
)

func Test_Base58(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    name := "Base58"
    data := "test-pass"

    en := FromString(data).Base58Encode()
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    de := FromString(enStr).Base58Decode()
    deStr := de.ToString()

    assertError(de.Error, name + " Decode error")

    assert(data, deStr, name)
}
