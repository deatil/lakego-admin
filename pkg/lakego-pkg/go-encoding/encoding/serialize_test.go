package encoding

import (
    "testing"
)

func Test_Serialize(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    name := "Serialize"
    data := map[string]string{
        "key": "test-pass",
        "key2": "test-pass-key2",
    }

    en := FromString("").SerializeEncode(data)
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    var deData map[string]string
    de := FromString(enStr).SerializeDecode(&deData)

    assertError(de.Error, name + " Decode error")

    assert(data["key"], deData["key"], name)
    assert(data["key2"], deData["key2"], name)
}
