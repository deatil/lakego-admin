package encoding

import (
    "bytes"
    "strings"
    "encoding/csv"
)

// Csv 编码
func CsvEncode(src [][]string) (string, error) {
    buf := bytes.NewBuffer(nil)

    w := csv.NewWriter(buf)
    w.WriteAll(src)

    if err := w.Error(); err != nil {
        return "", err
    }

    return buf.String(), nil
}

// Csv 解码
func CsvDecode(src string, opts ...rune) ([][]string, error) {
    r := csv.NewReader(strings.NewReader(src))

    if len(opts) > 0 {
        // ';'
        r.Comma = opts[0]
    }

    if len(opts) > 1 {
        // '#'
        r.Comment = opts[1]
    }

    return r.ReadAll()
}
