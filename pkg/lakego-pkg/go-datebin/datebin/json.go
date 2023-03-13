package datebin

import (
    "fmt"
    "bytes"
    "strconv"
)

// 生成
func (this Datebin) MarshalJSON() ([]byte, error) {
    return []byte(fmt.Sprintf(`"%s"`, this.ToDatetimeString())), nil
}

// 解出
func (this *Datebin) UnmarshalJSON(val []byte) error {
    c := Parse(string(bytes.Trim(val, `"`)))
    if c.Error() == nil {
        *this = c
    }

    return nil
}

// =============

// 日期时间
type DateTime struct {
    Datebin
}

// 生成
func (this DateTime) MarshalJSON() ([]byte, error) {
    return []byte(fmt.Sprintf(`"%s"`, this.ToDatetimeString())), nil
}

// 解出
func (this *DateTime) UnmarshalJSON(val []byte) error {
    c := Parse(string(bytes.Trim(val, `"`)))
    if c.Error() == nil {
        *this = DateTime{c}
    }

    return nil
}

// =============

// 日期
type Date struct {
    Datebin
}

// 生成
func (this Date) MarshalJSON() ([]byte, error) {
    return []byte(fmt.Sprintf(`"%s"`, this.ToDateString())), nil
}

// 解出
func (this *Date) UnmarshalJSON(val []byte) error {
    c := Parse(string(bytes.Trim(val, `"`)))
    if c.Error() == nil {
        *this = Date{c}
    }

    return nil
}

// =============

// 时间戳
type Timestamp struct {
    Datebin
}

// 生成
func (this Timestamp) MarshalJSON() ([]byte, error) {
    return []byte(fmt.Sprintf(`%d`, this.Timestamp())), nil
}

// 解出
func (this *Timestamp) UnmarshalJSON(val []byte) error {
    ts, err := strconv.ParseInt(string(val), 10, 64)
    if ts == 0 || err != nil {
        return err
    }

    c := FromTimestamp(ts)
    if c.Error() == nil {
        *this = Timestamp{c}
    }

    return nil
}
