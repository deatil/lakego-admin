package datebin

import (
    "time"
    "bytes"
)

// 原始格式
func (this Datebin) Layout(layout string) string {
    return this.time.In(this.loc).Format(layout)
}

// 时间字符
func (this Datebin) Parse(date string, format ...string) Datebin {
    var layout = ""

    if len(format) > 0 {
        layout = format[0]
    } else if len(format) == 0 && len(date) == 19 {
        layout = "Y-m-d H:i:s"
    } else if len(format) == 0 && len(date) == 10 {
        layout = "Y-m-d"
    } else {
        layout = "Y-m-d"
    }

    // 格式化
    layout = this.LayoutFormat(layout)
    time, err := time.Parse(layout, date)

    if err != nil {
        return this
    }

    this.time = time

    return this
}

// 格式化
func (this Datebin) Format(layout string) string {
    layout = this.LayoutFormat(layout)

    return this.Layout(layout)
}

// 格式化
func (this Datebin) LayoutFormat(str string) string {
    var buffer bytes.Buffer

    for i := 0; i < len(str); i++ {
        val, ok := Formats[str[i:i+1]]
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
