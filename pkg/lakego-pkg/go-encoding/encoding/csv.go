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

// ====================

// Csv
func (this Encoding) ForCsv(data [][]string) Encoding {
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

// Csv
func ForCsv(data [][]string) Encoding {
    return defaultEncode.ForCsv(data)
}

// Csv 编码输出
func (this Encoding) CsvTo(opts ...rune) ([][]string, error) {
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
