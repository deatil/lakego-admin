package encoding

import (
    "testing"
)

func Test_Base85(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    data := "test-pass"
    name := "Base85"

    en := FromString(data).Base85Encode()
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    de := FromString(enStr).Base85Decode()
    deStr := de.ToString()

    assertError(de.Error, name + " Decode error")

    assert(data, deStr, name)
}
