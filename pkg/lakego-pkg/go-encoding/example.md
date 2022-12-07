### 使用

~~~go
package main

import (
    "fmt"
    "github.com/deatil/go-encoding/encoding"
)

type Per struct {
    Name string
    Age int
}

func main() {
    // Base64 编码后结果
    base64Data := encoding.Base64Encode("useData").
    fmt.Println("Base64 编码后结果：", base64Data)

    // =====

    // Asn1 编码
    var p string
    encodeStr := encoding.ForAsn1("test-data").ToBase64String()
    encoding.FromBase64String("Ewl0ZXN0LWRhdGE=").Asn1To(&p)
    encodeStr2 := p

    // XML 编码
    p := Per{
        Name: "kkk",
        Age: 12,
    }

    var p2 Per

    // 编码
    encodeStr := encoding.ForXML(p).ToBase64String()
    encoding.FromBase64String("PFBlcj48TmFtZT5ra2s8L05hbWU+PEFnZT4xMjwvQWdlPjwvUGVyPg==").XMLTo(&p2)

    encodeStr2 := p2.Name

    // Binary 编码
    var p uint16
    encodeStr := encoding.ForBinary(uint16(61374)).ToBase64String()
    encoding.FromBase64String("vu8=").BinaryTo(&p)

    // Csv 编码
    records := [][]string{
        {"first_name", "last_name", "username"},
        {"Rob", "Pike", "rob"},
        {"Ken", "Thompson", "ken"},
        {"Robert", "Griesemer", "gri"},
    }
    in := `first_name,last_name,username
"Rob","Pike",rob
Ken,Thompson,ken
"Robert","Griesemer","gri"
`
    encodeStr := encoding.ForCsv(records).ToString()
    encodeStr2, _ := encoding.FromString(in).CsvTo()


    // Csv 编码2
    records := [][]string{
        {"first_name", "last_name", "username"},
        {"Rob", "Pike", "rob"},
        {"Ken", "Thompson", "ken"},
        {"Robert", "Griesemer", "gri"},
    }
    in := `first_name;last_name;username
"Rob";"Pike";rob
# lines beginning with a # character are ignored
Ken;Thompson;ken
"Robert";"Griesemer";"gri"
`
    encodeStr := encoding.ForCsv(records).ToString()
    encodeStr2, _ := encoding.FromString(in).CsvTo(';', '#')
}

~~~
