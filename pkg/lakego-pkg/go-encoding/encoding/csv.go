package encoding

import (
    "bytes"
    "errors"
    "strings"
    "reflect"
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
func (this Encoding) CsvDecode(dst any, opts ...rune) Encoding {
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

    csvs, err := r.ReadAll()
    if err != nil {
        this.Error = err
        return this
    }

    // 获取最后指针
    dstValue := reflect.ValueOf(dst)
    for dstValue.Kind() == reflect.Pointer {
        dstValue = dstValue.Elem()
    }

    if !dstValue.IsValid() || dstValue.Kind() != reflect.Slice {
        this.Error = errors.New("Decode to data type is not slice")
        return this
    }

    if !dstValue.CanSet() {
        this.Error = errors.New("Decode to data not set")
        return this
    }

    dstData := make([]reflect.Value, 0)
    for _, csv := range csvs {
        dstData = append(dstData, reflect.ValueOf(csv))
    }

    dstDataArr := reflect.Append(dstValue, dstData...)

    dstValue.Set(dstDataArr)

    return this
}
