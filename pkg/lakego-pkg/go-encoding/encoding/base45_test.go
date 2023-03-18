package encoding

import (
    "testing"
)

func Test_Base45(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    name := "Base45"
    data := "test-pass"

    en := FromString(data).Base45Encode()
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    de := FromString(enStr).Base45Decode()
    deStr := de.ToString()

    assertError(de.Error, name + " Decode error")

    assert(data, deStr, name)
}
