package encoding

import (
    "testing"
)

func Test_Quotedprintable(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    name := "Quotedprintable"
    data := `quoted\nprin\rtabl e gt\tdf`

    en := FromString(data).QuotedprintableEncode()
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    de := FromString(enStr).QuotedprintableDecode()
    deStr := de.ToString()

    assertError(de.Error, name + " Decode error")

    assert(data, deStr, name)
}
