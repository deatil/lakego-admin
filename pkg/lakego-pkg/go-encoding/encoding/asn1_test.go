package encoding

import (
    "testing"
)

func Test_Asn1(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    name := "Asn1"
    data := "test-pass"

    en := FromString("").Asn1Encode(data)
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    var deStr string
    de := FromString(enStr).Asn1Decode(&deStr)

    assertError(de.Error, name + " Decode error")

    assert(data, deStr, name)
}

func Test_Asn1Params(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    name := "Asn1Params"
    data := "test-pass"
    params := "testparams"

    en := FromString("").Asn1EncodeWithParams(data, params)
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    var deStr string
    de := FromString(enStr).Asn1DecodeWithParams(&deStr, params)

    assertError(de.Error, name + " Decode error")

    assert(data, deStr, name)
}
