package encoding

import (
    "testing"
)

func Test_Gob(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    name := "Gob"
    data := map[string]string{
        "key": "test-pass",
        "key2": "test-pass-Gob",
    }

    en := FromString("").GobEncode(data)
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    var deData map[string]string
    de := FromString(enStr).GobDecode(&deData)

    assertError(de.Error, name + " Decode error")

    assert(data["key"], deData["key"], name)
    assert(data["key2"], deData["key2"], name)
}
