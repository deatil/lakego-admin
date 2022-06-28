package datebin

import (
    "fmt"
    "bytes"
    "strconv"
)

// 默认返回
func (this Datebin) String() string {
    return this.ToDatetimeString()
}

// 返回字符
func (this Datebin) ToString(timezone ...string) string {
    if len(timezone) > 0 {
        this.loc, this.Error = this.GetLocationByTimezone(timezone[0])
    }

    if this.IsInvalid() {
        return ""
    }

    return this.time.In(this.loc).String()
}

// 返回星座名称
func (this Datebin) ToStarString(timezone ...string) string {
    if len(timezone) > 0 {
        this.loc, this.Error = this.GetLocationByTimezone(timezone[0])
    }

    if this.IsInvalid() {
        return ""
    }

    // 月份和天数
    month := this.Month()
    day := this.Day()

    // 星座英文名称
    star := ""
    switch {
        // 摩羯座
        case month == 12 && day >= 22, month == 1 && day <= 19:
            star = "Capricorn"
        // 水瓶座
        case month == 1 && day >= 20, month == 2 && day <= 18:
            star = "Aquarius"
        // 双鱼座
        case month == 2 && day >= 19, month == 3 && day <= 20:
            star = "Pisces"
        // 白羊座
        case month == 3 && day >= 21, month == 4 && day <= 20:
            star = "Aries"
        // 金牛座
        case month == 4 && day >= 21, month == 5 && day <= 20:
            star = "Taurus"
        // 双子座
        case month == 5 && day >= 21, month == 6 && day <= 21:
            star = "Gemini"
        // 巨蟹座
        case month == 6 && day >= 22, month == 7 && day <= 22:
            star = "Cancer"
        // 狮子座
        case month == 7 && day >= 23, month == 8 && day <= 22:
            star = "Leo"
        // 处女座
        case month == 8 && day >= 23, month == 9 && day <= 22:
            star = "Virgo"
        // 天秤座
        case month == 9 && day >= 23, month == 10 && day <= 23:
            star = "Libra"
        // 天蝎座
        case month == 10 && day >= 24, month == 11 && day <= 22:
            star = "Scorpio"
        // 射手座
        case month == 11 && day >= 23, month == 12 && day <= 21:
            star = "Sagittarius"
    }

    return star
}

// 返回当前季节，以气象划分
func (this Datebin) ToSeasonString(timezone ...string) string {
    if len(timezone) > 0 {
        this.loc, this.Error = this.GetLocationByTimezone(timezone[0])
    }

    if this.IsInvalid() {
        return ""
    }

    // 月份
    month := this.Month()

    name := ""
    switch {
        // 春季
        case month == 3 || month == 4 || month == 5:
            name = "Spring"
        // 夏季
        case month == 6 || month == 7 || month == 8:
            name = "Summer"
        // 秋季
        case month == 9 || month == 10 || month == 11:
            name = "Autumn"
        // 冬季
        case month == 12 || month == 1 || month == 2:
            name = "Winter"
    }

    return name
}

// 周几
func (this Datebin) ToWeekdayString(timezone ...string) string {
    if len(timezone) > 0 {
        this.loc, this.Error = this.GetLocationByTimezone(timezone[0])
    }

    if this.IsInvalid() {
        return ""
    }

    weekday := this.Weekday()

    return Weekdays[weekday]
}

// 原始格式
func (this Datebin) Layout(layout string, timezone ...string) string {
    if len(timezone) > 0 {
        this.loc, this.Error = this.GetLocationByTimezone(timezone[0])
    }

    if this.Error != nil {
        return ""
    }

    return this.time.In(this.loc).Format(layout)
}

// 原始格式
func (this Datebin) ToLayoutString(layout string, timezone ...string) string {
    return this.Layout(layout, timezone...)
}

// 输出指定布局的时间字符串
func (this Datebin) Format(layout string, timezone ...string) string {
    if len(timezone) > 0 {
        this.loc, this.Error = this.GetLocationByTimezone(timezone[0])
    }

    if this.IsInvalid() {
        return ""
    }

    var buffer bytes.Buffer

    // 字符解析
    for i := 0; i < len(layout); i++ {
        val, ok := ToFormats[layout[i:i+1]]
        if ok {
            buffer.WriteString(this.time.In(this.loc).Format(val))
        } else {
            switch layout[i] {
                case '\\':
                    buffer.WriteByte(layout[i+1])
                    i++
                    continue
                case 'W': // ISO-8601 格式数字表示的年份中的第几周，取值范围 1-52
                    buffer.WriteString(strconv.Itoa(this.WeekOfYear()))
                case 'N': // ISO-8601 格式数字表示的星期中的第几天，取值范围 1-7
                    buffer.WriteString(strconv.Itoa(this.DayOfWeek()))
                case 'S': // 月份中第几天的英文缩写后缀，如st, nd, rd, th
                    suffix := "th"
                    switch this.Day() {
                        case 1, 21, 31:
                            suffix = "st"
                        case 2, 22:
                            suffix = "nd"
                        case 3, 23:
                            suffix = "rd"
                    }

                    buffer.WriteString(suffix)
                case 'G': // 数字表示的小时，24 小时格式，没有前导零
                    buffer.WriteString(strconv.Itoa(this.Hour()))
                case 'U': // 秒级时间戳
                    buffer.WriteString(strconv.FormatInt(this.Timestamp(), 10))
                case 'u': // 数字表示的微秒，补位为固定6位
                    buffer.WriteString(fmt.Sprintf("%06d", this.Microsecond()))
                case 'w': // 数字表示的星期中的第几天
                    buffer.WriteString(strconv.Itoa(this.DayOfWeek()))
                case 't': // 指定的月份有几天
                    buffer.WriteString(strconv.Itoa(this.DaysInMonth()))
                case 'z': // 年份中的第几天
                    buffer.WriteString(strconv.Itoa(this.DayOfYear() - 1))
                case 'e': // 当前位置
                    buffer.WriteString(this.GetLocationString())
                case 'Q': // 当前季度
                    buffer.WriteString(strconv.Itoa(this.Quarter()))
                case 'C': // 当前百年数
                    buffer.WriteString(strconv.Itoa(this.Century()))
                case 'o': // 当前年数
                    buffer.WriteString(strconv.Itoa(this.Year()))
                case 'L': // 是否为闰年
                    if this.IsLeapYear() {
                        buffer.WriteString("ly")
                    } else {
                        buffer.WriteString("nly")
                    }
                default:
                    buffer.WriteByte(layout[i])
            }
        }
    }

    return buffer.String()
}

// 格式化
func (this Datebin) ToFormatString(layout string, timezone ...string) string {
    return this.Format(layout, timezone...)
}

// 输出 Ansic 格式字符串
func (this Datebin) ToAnsicString(timezone ...string) string {
    return this.ToLayoutString(AnsicFormat, timezone...)
}

// 输出 UnixDate 格式字符串
func (this Datebin) ToUnixDateString(timezone ...string) string {
    return this.ToLayoutString(UnixDateFormat, timezone...)
}

// 输出 RubyDate 格式字符串
func (this Datebin) ToRubyDateString(timezone ...string) string {
    return this.ToLayoutString(RubyDateFormat, timezone...)
}

// 输出 RFC822 格式字符串
func (this Datebin) ToRFC822String(timezone ...string) string {
    return this.ToLayoutString(RFC822Format, timezone...)
}

// 输出 RFC822Z 格式字符串
func (this Datebin) ToRFC822ZString(timezone ...string) string {
    return this.ToLayoutString(RFC822ZFormat, timezone...)
}

// 输出 RFC850 格式字符串
func (this Datebin) ToRFC850String(timezone ...string) string {
    return this.ToLayoutString(RFC850Format, timezone...)
}

// 输出 RFC1123 格式字符串
func (this Datebin) ToRFC1123String(timezone ...string) string {
    return this.ToLayoutString(RFC1123Format, timezone...)
}

// 输出 RFC1123Z 格式字符串
func (this Datebin) ToRFC1123ZString(timezone ...string) string {
    return this.ToLayoutString(RFC1123ZFormat, timezone...)
}

// 输出 Rss 格式字符串
func (this Datebin) ToRssString(timezone ...string) string {
    return this.ToLayoutString(RssFormat, timezone...)
}

// 输出 RFC2822 格式字符串
func (this Datebin) ToRFC2822String(timezone ...string) string {
    return this.ToLayoutString(RFC2822Format, timezone...)
}

// 输出 RFC3339 格式字符串
func (this Datebin) ToRFC3339String(timezone ...string) string {
    return this.ToLayoutString(RFC3339Format, timezone...)
}

// 输出 Kitchen 格式字符串
func (this Datebin) ToKitchenString(timezone ...string) string {
    return this.ToLayoutString(KitchenFormat, timezone...)
}

// 输出 Cookie 格式字符串
func (this Datebin) ToCookieString(timezone ...string) string {
    return this.ToLayoutString(CookieFormat, timezone...)
}

// 输出 ISO8601 格式字符串
func (this Datebin) ToISO8601String(timezone ...string) string {
    return this.ToLayoutString(ISO8601Format, timezone...)
}

// 输出 RFC1036 格式字符串
func (this Datebin) ToRFC1036String(timezone ...string) string {
    return this.ToLayoutString(RFC1036Format, timezone...)
}

// 输出 RFC7231 格式字符串
func (this Datebin) ToRFC7231String(timezone ...string) string {
    return this.ToLayoutString(RFC7231Format, timezone...)
}

// 输出 ATOM 格式字符串
func (this Datebin) ToAtomString(timezone ...string) string {
    return this.ToRFC3339String(timezone...)
}

// 输出 W3C 格式字符串
func (this Datebin) ToW3CString(timezone ...string) string {
    return this.ToRFC3339String(timezone...)
}

// 输出 DayDateTime 格式字符串
func (this Datebin) ToDayDateTimeString(timezone ...string) string {
    return this.ToLayoutString(DayDateTimeFormat, timezone...)
}

// 输出 FormattedDate 格式字符串
func (this Datebin) ToFormattedDateString(timezone ...string) string {
    return this.ToLayoutString(FormattedDateFormat, timezone...)
}

// 日期时间
func (this Datebin) ToDatetimeString(timezone ...string) string {
    return this.ToLayoutString(DatetimeFormat, timezone...)
}

// 日期
func (this Datebin) ToDateString(timezone ...string) string {
    return this.ToLayoutString(DateFormat, timezone...)
}

// 时间
func (this Datebin) ToTimeString(timezone ...string) string {
    return this.ToLayoutString(TimeFormat, timezone...)
}

// 输出 ShortDatetime 格式字符串
func (this Datebin) ToShortDatetimeString(timezone ...string) string {
    return this.ToLayoutString(ShortDatetimeFormat, timezone...)
}

// 输出 ShortDate 格式字符串
func (this Datebin) ToShortDateString(timezone ...string) string {
    return this.ToLayoutString(ShortDateFormat, timezone...)
}

// 输出 ShortTime 格式字符串
func (this Datebin) ToShortTimeString(timezone ...string) string {
    return this.ToLayoutString(ShortTimeFormat, timezone...)
}
