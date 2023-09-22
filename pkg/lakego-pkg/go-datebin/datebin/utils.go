package datebin

import (
    "time"
)

// 通过时区获取 Location 实例
func (this Datebin) GetLocationByTimezone(timezone string) (*time.Location, error) {
    return time.LoadLocation(timezone)
}

// 通过持续时长解析
func (this Datebin) ParseDuration(duration string) (time.Duration, error) {
    return time.ParseDuration(duration)
}

// 取绝对值
func (this Datebin) AbsFormat(value int64) int64 {
    if value < 0 {
        return -value
    }

    return value
}
