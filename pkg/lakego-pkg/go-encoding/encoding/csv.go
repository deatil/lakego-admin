package encoding

import (
    "bytes"
    "strings"
    "encoding/csv"
)

// Csv
func (this Encoding) CsvEncode(data [][]string) Encoding {
    buf := bytes.NewBuffer(nil)

    w := csv.NewWriter(buf)
    w.WriteAll(data)

    if err := w.Error(); err != nil {
        this.Error = err
        return this
    }

    this.data = buf.Bytes()

    return this
}

// Csv 编码输出
func (this Encoding) CsvDecode(opts ...rune) ([][]string, error) {
    buf := strings.NewReader(string(this.data))
    r := csv.NewReader(buf)

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
