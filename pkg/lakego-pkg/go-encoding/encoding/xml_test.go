package encoding

import (
    "testing"
)

func Test_Xml(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    type Per struct {
        Name string
        Age int
    }

    name := "Xml"
    data := Per{
        Name: "kkk",
        Age: 12,
    }

    en := FromString("").XmlEncode(data)
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")

    var deData Per
    de := FromString(enStr).XmlDecode(&deData)

    assertError(de.Error, name + " Decode error")

    assert(data.Name, deData.Name, name)
    assert(data.Age, data.Age, name)
}
