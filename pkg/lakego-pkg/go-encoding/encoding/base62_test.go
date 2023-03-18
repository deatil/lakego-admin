package encoding

import (
    "testing"
)

func Test_Base62(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    data := "test-pass"
    name := "Base62"

    en := FromString(data).Base62Encode()
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    de := FromString(enStr).Base62Decode()
    deStr := de.ToString()

    assertError(de.Error, name + " Decode error")

    assert(data, deStr, name)
}
