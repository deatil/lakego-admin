package datebin

import (
	"bytes"
)

// 取绝对值
// abs data format
func absFormat(value int64) int64 {
	if value < 0 {
		return -value
	}

	return value
}

// 解析格式化字符
// parse format string data
func parseFormatString(str string) string {
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
