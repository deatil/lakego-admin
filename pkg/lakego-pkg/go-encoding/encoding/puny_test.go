package encoding

import (
    "testing"
)

func Test_Puny(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    name := "Puny"
    data := "ó チツチノハフヘキキξεζοреё┢┣┮┐┑ 《《"

    en := FromString(data).PunyEncode()
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    de := FromString(enStr).PunyDecode()
    deStr := de.ToString()

    assertError(de.Error, name + " Decode error")

    assert(data, deStr, name)
}
