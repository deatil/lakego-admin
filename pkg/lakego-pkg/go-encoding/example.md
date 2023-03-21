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
    base64Data := encoding.
        FromString("use-data"). // 数据来源
        Base64Encode().      // 编码或者解码方式
        ToString()           // 输出结果
    fmt.Println("Base64 编码后结果：", base64Data)

    // =====

    // Asn1 编码
    var p string
    encodeStr := encoding.Asn1Encode("test-data").Base64Encode().ToString()
    encoding.FromString("Ewl0ZXN0LWRhdGE=").Base64Decode().Asn1Decode(&p)
    encodeStr2 := p

    // XML 编码
    p := Per{
        Name: "kkk",
        Age: 12,
    }

    var p2 Per

    // 编码
    encodeStr := encoding.XmlEncode(p).Base64Encode().ToString()
    encoding.FromString("PFBlcj48TmFtZT5ra2s8L05hbWU+PEFnZT4xMjwvQWdlPjwvUGVyPg==").Base64Decode().XmlDecode(&p2)

    encodeStr2 := p2.Name

    // Binary 编码
    var p uint16
    encodeStr := encoding.BinaryLittleEndianEncode(uint16(61374)).Base64Encode().ToString()
    encoding.FromString("vu8=").Base64Decode().XmlDecode(&p)

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
    encodeStr := encoding.CsvEncode(records).ToString()

    var encodeStr2 [][]string
    encoding.FromString(in).CsvDecode(&encodeStr2)


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
    encodeStr := encoding.CsvEncode(records).ToString()

    var encodeStr2 [][]string
    encoding.FromString(in).CsvDecode(&encodeStr2, ';', '#')
}

~~~
