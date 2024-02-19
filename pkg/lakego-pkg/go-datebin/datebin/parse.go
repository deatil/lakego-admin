package datebin

import (
	"strconv"
	"strings"
	"time"
)

// 解析时间字符
// Parse date string
func (this Datebin) Parse(date string, timezone ...string) Datebin {
	// 解析需要的格式
	var layout = DatetimeFormat

	if _, err := strconv.ParseInt(date, 10, 64); err == nil {
		switch {
		case len(date) == 8:
			layout = ShortDateFormat
		case len(date) == 14:
			layout = ShortDatetimeFormat
		}
	} else {
		switch {
		case len(date) == 10 &&
			strings.Count(date, "-") == 2:
			layout = DateFormat
		case len(date) == 19 &&
			strings.Count(date, "-") == 2 &&
			strings.Count(date, ":") == 2:
			layout = DatetimeFormat
		case len(date) == 23 &&
			strings.Count(date, "-") == 2 &&
			strings.Count(date, ":") == 2 &&
			strings.Index(date, ".") == 19:
			layout = DatetimeMilliFormat
		case len(date) == 26 &&
			strings.Count(date, "-") == 2 &&
			strings.Count(date, ":") == 2 &&
			strings.Index(date, ".") == 19:
			layout = DatetimeMicroFormat
		case len(date) == 29 &&
			strings.Count(date, "-") == 2 &&
			strings.Count(date, ":") == 2 &&
			strings.Index(date, ".") == 19:
			layout = DatetimeNanoFormat
		case len(date) == 18 && strings.Index(date, ".") == 14:
			layout = ShortDatetimeMilliFormat
		case len(date) == 21 && strings.Index(date, ".") == 14:
			layout = ShortDatetimeMicroFormat
		case len(date) == 24 && strings.Index(date, ".") == 14:
			layout = ShortDatetimeNanoFormat
		case len(date) == 25 && strings.Index(date, "T") == 10:
			layout = RFC3339Format
		case len(date) == 29 && strings.Index(date, "T") == 10 &&
			strings.Index(date, ".") == 19:
			layout = RFC3339MilliFormat
		case len(date) == 32 && strings.Index(date, "T") == 10 &&
			strings.Index(date, ".") == 19:
			layout = RFC3339MicroFormat
		case len(date) == 35 && strings.Index(date, "T") == 10 &&
			strings.Index(date, ".") == 19:
			layout = RFC3339NanoFormat
		}
	}

	time, err := time.Parse(layout, date)
	if err != nil {
		return this.AppendError(err)
	}

	if len(timezone) > 0 {
		this = this.SetTimezone(timezone[0])
	}

	this.time = time

	return this
}

// 解析时间字符
// Parse date string
func Parse(date string, timezone ...string) Datebin {
	return defaultDatebin.Parse(date, timezone...)
}

// 用布局字符解析时间字符
// Parse date string with layout
func (this Datebin) ParseWithLayout(date string, layout string, timezone ...string) Datebin {
	if len(timezone) > 0 {
		this = this.SetTimezone(timezone[0])
	}

	time, err := time.ParseInLocation(layout, date, this.loc)
	if err != nil {
		return this.AppendError(err)
	}

	this.time = time

	return this
}

// 用布局字符解析时间字符
// Parse date string with layout
func ParseWithLayout(date string, layout string, timezone ...string) Datebin {
	return defaultDatebin.ParseWithLayout(date, layout, timezone...)
}

// 用格式化字符解析时间字符
// Parse date string with format
func (this Datebin) ParseWithFormat(date string, format string, timezone ...string) Datebin {
	return this.ParseWithLayout(date, parseFormatString(format), timezone...)
}

// 用格式化字符解析时间字符
// Parse date string with format
func ParseWithFormat(date string, format string, timezone ...string) Datebin {
	return defaultDatebin.ParseWithFormat(date, format, timezone...)
}

// 用格式化字符或者布局字符解析时间字符
// Parse date string with format or layout
func ParseDatetimeString(date string, format ...string) Datebin {
	if len(format) > 1 && format[1] == "u" {
		return ParseWithFormat(date, format[0])
	}

	if len(format) > 0 {
		return ParseWithLayout(date, format[0])
	}

	return Parse(date)
}
