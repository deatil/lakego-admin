package datebin

import (
	"bytes"
	"fmt"
	"strconv"
)

// 转换为 json
// Marshal to JSON
func (this Datebin) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, this.ToDatetimeString())), nil
}

// 解析 json
// Unmarshal JSON data
func (this *Datebin) UnmarshalJSON(val []byte) error {
	c := Parse(string(bytes.Trim(val, `"`)))
	if c.Error() == nil {
		*this = c
	}

	return nil
}

// =============

// 日期时间
// DateTime struct
type DateTime Datebin

// 转换为 json
// Marshal to JSON
func (this DateTime) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, Datebin(this).ToDatetimeString())), nil
}

// 解析 json
// Unmarshal JSON data
func (this *DateTime) UnmarshalJSON(val []byte) error {
	c := Parse(string(bytes.Trim(val, `"`)))
	if c.Error() == nil {
		*this = DateTime(c)
	}

	return nil
}

// =============

// 日期
// Date struct
type Date Datebin

// 转换为 json
// Marshal to JSON
func (this Date) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, Datebin(this).ToDateString())), nil
}

// 解析 json
// Unmarshal JSON data
func (this *Date) UnmarshalJSON(val []byte) error {
	c := Parse(string(bytes.Trim(val, `"`)))
	if c.Error() == nil {
		*this = Date(c)
	}

	return nil
}

// =============

// 时间戳
// Timestamp struct
type Timestamp Datebin

// 转换为 json
// Marshal to JSON
func (this Timestamp) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`%d`, Datebin(this).Timestamp())), nil
}

// 解析 json
// Unmarshal JSON data
func (this *Timestamp) UnmarshalJSON(val []byte) error {
	ts, err := strconv.ParseInt(string(val), 10, 64)
	if ts == 0 || err != nil {
		return err
	}

	c := FromTimestamp(ts)
	if c.Error() == nil {
		*this = Timestamp(c)
	}

	return nil
}
