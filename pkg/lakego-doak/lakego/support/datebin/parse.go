package datebin

import (
    "time"
    "bytes"
)

// 解析时间字符
func (this Datebin) Parse(date string, format ...string) Datebin {
    var layout = ""

    if len(format) > 0 {
        layout = format[0]
    } else if len(format) == 0 && len(date) == 19 {
        layout = "Y-m-d H:i:s"
    } else if len(format) == 0 && len(date) == 10 {
        layout = "Y-m-d"
    } else {
        layout = "Y-m-d H:i:s"
    }

    // 格式化
    layout = this.FormatParseLayout(layout)
    time, err := time.Parse(layout, date)

    if err != nil {
        return this
    }

    this.time = time

    return this
}

// 格式化解析 layout
func (this Datebin) FormatParseLayout(str string) string {
    var buffer bytes.Buffer

    for i := 0; i < len(str); i++ {
        val, ok := PaseFormats[str[i:i+1]]
        if ok {
            buffer.WriteString(val)
        } else {
            switch str[i] {
                case '\\':
                    buffer.WriteByte(str[i+1])
                    i++
                    continue
                default:
                    buffer.WriteByte(str[i])
            }
        }
    }

    return buffer.String()
}
