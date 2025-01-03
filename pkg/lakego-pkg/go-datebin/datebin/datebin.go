package datebin

import (
	"errors"
	"time"
)

var (
	// 解析的格式字符
	// parse format list
	PaseFormats = map[string]string{
		"D": "Mon",
		"d": "02",
		"N": "Monday",
		"j": "2",
		"l": "Monday",
		"z": "__2",

		"F": "January",
		"m": "01",
		"M": "Jan",
		"n": "1",

		"Y": "2006",
		"y": "06",

		"a": "pm",
		"A": "PM",
		"g": "3",
		"G": "=G=15",
		"h": "03",
		"H": "15",
		"i": "04",
		"s": "05",
		"u": "000000",

		"O": "-0700",
		"P": "-07:00",
		"T": "MST",

		"c": "2006-01-02T15:04:05Z07:00",
		"r": "Mon, 02 Jan 2006 15:04:05 -0700",
	}

	// 输出的格式字符
	// output format list
	ToFormats = map[string]string{
		"D": "Mon",
		"d": "02",
		"j": "2",
		"l": "Monday",

		"F": "January",
		"m": "01",
		"M": "Jan",
		"n": "1",

		"Y": "2006",
		"y": "06",

		"a": "pm",
		"A": "PM",
		"g": "3",
		"h": "03",
		"H": "15",
		"i": "04",
		"s": "05",

		"O": "-0700",
		"P": "-07:00",
		"T": "MST",

		"c": "2006-01-02T15:04:05Z07:00",
		"r": "Mon, 02 Jan 2006 15:04:05 -0700",
	}

	// 月份
	// Month list
	Months = map[int]time.Month{
		1:  time.January,
		2:  time.February,
		3:  time.March,
		4:  time.April,
		5:  time.May,
		6:  time.June,
		7:  time.July,
		8:  time.August,
		9:  time.September,
		10: time.October,
		11: time.November,
		12: time.December,
	}

	// 周列表
	// Weekday list
	Weekdays = []string{
		"Sunday",
		"Monday",
		"Tuesday",
		"Wednesday",
		"Thursday",
		"Friday",
		"Saturday",
	}
)

// 默认
// default Datebin
var defaultDatebin = NewDatebin()

/**
 * 日期 / Datebin
 *
 * @create 2022-3-6
 * @author deatil
 */
type Datebin struct {
	// 时间 / Time
	time time.Time

	// 周开始 / week Start
	weekStartAt time.Weekday

	// 时区 / Location
	loc *time.Location

	// 错误 / error list
	Errors []error
}

// New Datebin
func NewDatebin() Datebin {
	return Datebin{
		loc:         time.Local,
		weekStartAt: time.Monday,
	}
}

// New Datebin
func New() Datebin {
	return NewDatebin()
}

// 设置时间
// set Time
func (this Datebin) WithTime(time time.Time) Datebin {
	this.time = time
	return this
}

// 获取时间
// Get Time
func (this Datebin) GetTime() time.Time {
	return this.time
}

// 设置周开始时间
// set Start Week
func (this Datebin) WithWeekStartAt(weekday time.Weekday) Datebin {
	this.weekStartAt = weekday
	return this
}

// 获取周开始时间
// Get Start Week
func (this Datebin) GetWeekStartAt() time.Weekday {
	return this.weekStartAt
}

// 设置时区
// set Location struct
func (this Datebin) WithLocation(loc *time.Location) Datebin {
	this.loc = loc
	return this
}

// 获取时区
// Get Location struct
func (this Datebin) GetLocation() *time.Location {
	return this.loc
}

// 获取时区字符
// Get Location String
func (this Datebin) GetLocationString() string {
	return this.loc.String()
}

// 设置时区
// Set Timezone
func (this Datebin) SetTimezone(timezone string) Datebin {
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return this.AppendError(err)
	}

	this.loc = loc

	return this
}

// 全局设置时区
// Set global Timezone
func SetTimezone(timezone string) {
	defaultDatebin = defaultDatebin.SetTimezone(timezone)
}

// 获取时区 Zone 名称
// Get Timezone string
func (this Datebin) GetTimezone() string {
	name, _ := this.time.Zone()
	return name
}

// 获取距离UTC时区的偏移量，单位秒
// Get Zone Offset
func (this Datebin) GetOffset() int {
	_, offset := this.time.Zone()
	return offset
}

// 获取时区数据
// Get Zone data
func (this Datebin) GetZone() (string, int) {
	return this.time.Zone()
}

// 设置 UTC
// set UTC timezone
func (this Datebin) UTC() Datebin {
	this.loc = time.UTC
	return this
}

// 设置 Local
// set Local timezone
func (this Datebin) Local() Datebin {
	this.loc = time.Local
	return this
}

// FixedZone 设置时区
// FixedZone returns a Location that always uses
// the given zone name and offset (seconds east of UTC).
func (this Datebin) FixedZone(name string, offset int) Datebin {
	this.loc = time.FixedZone(name, offset)
	return this
}

// 覆盖错误信息
// set Errors
func (this Datebin) WithErrors(errs []error) Datebin {
	this.Errors = errs
	return this
}

// 获取错误信息
// Get Errors
func (this Datebin) GetErrors() []error {
	return this.Errors
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (this Datebin) MarshalBinary() ([]byte, error) {
	enc := []byte{
		byte(this.weekStartAt),
	}

	tt := this.time.In(this.loc)

	timeBytes, err := tt.MarshalBinary()
	if err != nil {
		return nil, err
	}

	enc = append(enc, timeBytes...)

	return enc, nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (this *Datebin) UnmarshalBinary(data []byte) error {
	buf := data
	if len(buf) == 0 {
		return errors.New("Datebin.UnmarshalBinary: no data")
	}

	weekStartAt := buf[0]

	err := (&this.time).UnmarshalBinary(buf[1:])
	if err != nil {
		return err
	}

	this.loc = this.time.Location()

	this.weekStartAt = time.Weekday(weekStartAt)

	return nil
}

// GobEncode implements the gob.GobEncoder interface.
func (this Datebin) GobEncode() ([]byte, error) {
	return this.MarshalBinary()
}

// GobDecode implements the gob.GobDecoder interface.
func (this *Datebin) GobDecode(data []byte) error {
	return this.UnmarshalBinary(data)
}
