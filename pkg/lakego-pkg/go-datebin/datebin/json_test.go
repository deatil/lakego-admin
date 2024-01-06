package datebin

import (
    "testing"
    "encoding/json"
)

type testMarshalJSON1 struct {
    Date Datebin
    Str string
}

func Test_MarshalJSON(t *testing.T) {
    eq := assertEqualT(t)

    date := Parse("2024-06-05 21:15:12")
    str := "Datebin Json"

    check0 := `{"Date":"2024-06-06 05:15:12","Str":"Datebin Json"}`

    check := testMarshalJSON1{
        Date: date,
        Str: str,
    }

    marshaled, err := json.Marshal(check)
    if err != nil {
        t.Fatal(err)
    }

    var dst testMarshalJSON1
    err = json.Unmarshal(marshaled, &dst)
    if err != nil {
        t.Fatal(err)
    }

    eq(string(marshaled), check0, "failed MarshalJSON")
    eq(dst.Str, check.Str, "failed MarshalJSON")
    eq(dst.Date.ToDatetimeString(UTC), date.ToDatetimeString(), "failed MarshalJSON")
}

type testMarshalJSON2 struct {
    Date DateTime
    Str string
}

func Test_MarshalJSON_DateTime(t *testing.T) {
    eq := assertEqualT(t)

    date := Parse("2024-06-05 21:15:12")
    str := "Datebin DateTime Json"

    check0 := `{"Date":"2024-06-06 05:15:12","Str":"Datebin DateTime Json"}`

    check := testMarshalJSON2{
        Date: DateTime(date),
        Str: str,
    }

    marshaled, err := json.Marshal(check)
    if err != nil {
        t.Fatal(err)
    }

    var dst testMarshalJSON2
    err = json.Unmarshal(marshaled, &dst)
    if err != nil {
        t.Fatal(err)
    }

    eq(string(marshaled), check0, "failed MarshalJSON DateTime")
    eq(dst.Str, check.Str, "failed MarshalJSON DateTime")
    eq(Datebin(dst.Date).ToDatetimeString(UTC), date.ToDatetimeString(), "failed MarshalJSON DateTime")
}

type testMarshalJSON3 struct {
    Date Date
    Str string
}

func Test_MarshalJSON_Date(t *testing.T) {
    eq := assertEqualT(t)

    date := Parse("2024-06-05 21:15:12")
    str := "Datebin Date Json"

    check0 := `{"Date":"2024-06-06","Str":"Datebin Date Json"}`

    check := testMarshalJSON3{
        Date: Date(date),
        Str: str,
    }

    marshaled, err := json.Marshal(check)
    if err != nil {
        t.Fatal(err)
    }

    var dst testMarshalJSON3
    err = json.Unmarshal(marshaled, &dst)
    if err != nil {
        t.Fatal(err)
    }

    eq(string(marshaled), check0, "failed MarshalJSON Date")
    eq(dst.Str, check.Str, "failed MarshalJSON Date")
    eq(Datebin(dst.Date).ToDateString(UTC), date.ToDateString(), "failed MarshalJSON Date")
}

type testMarshalJSON31 struct {
    Date Timestamp
    Str string
}

func Test_MarshalJSON_Timestamp(t *testing.T) {
    eq := assertEqualT(t)

    date := Parse("2024-06-05 21:15:12")
    str := "Datebin Timestamp Json"

    check0 := `{"Date":1717622112,"Str":"Datebin Timestamp Json"}`

    check := testMarshalJSON31{
        Date: Timestamp(date),
        Str: str,
    }

    marshaled, err := json.Marshal(check)
    if err != nil {
        t.Fatal(err)
    }

    var dst testMarshalJSON31
    err = json.Unmarshal(marshaled, &dst)
    if err != nil {
        t.Fatal(err)
    }

    eq(string(marshaled), check0, "failed MarshalJSON Date")
    eq(dst.Str, check.Str, "failed MarshalJSON Date")
    eq(Datebin(dst.Date).ToDatetimeString(), date.ToDatetimeString(), "failed MarshalJSON Date")
}
