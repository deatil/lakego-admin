package encoding

import (
    "testing"
)

func Test_Csv(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    name := "Csv"

    records := [][]string{
        {"first_name", "last_name", "username"},
        {"Rob", "Pike", "rob"},
        {"Ken", "Thompson", "ken"},
        {"Robert", "Griesemer", "gri"},
    }
    in := `first_name,last_name,username
Rob,Pike,rob
Ken,Thompson,ken
Robert,Griesemer,gri
`

    en := FromString("").CsvEncode(records)
    enStr := en.ToString()

    assertError(en.Error, name + " Encode error")
    assert(in, enStr, name + " Encode")

    deStr, deErr := FromString(in).CsvDecode()

    assertError(deErr, name + " Decode error")
    assert(records, deStr, name + " Decode")
}
