package datebin

import (
    "testing"
)

func Test_DatetimeAll(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        century int
        decade int
        quarter int
        weekday int
        millisecond, microsecond, nanosecond int
        timestamp int64
        timestampWithSecond int64
        timestampWithMillisecond int64
        timestampWithMicrosecond int64
        timestampWithNanosecond int64
        year, month, day, hour, minute, second int
    } {
        {
            index: "index-1",
            date: "2025-06-07 06:35:23",
            century: 21,
            decade: 20,
            quarter: 2,
            weekday: 6,
            millisecond: 0,
            microsecond: 0,
            nanosecond: 0,
            timestamp: 1749278123,
            timestampWithSecond: 1749278123,
            timestampWithMillisecond: 1749278123000,
            timestampWithMicrosecond: 1749278123000000,
            timestampWithNanosecond: 1749278123000000000,
            year: 2025,
            month: 06,
            day: 07,
            hour: 06,
            minute: 35,
            second: 23,
        },
        {
            index: "index-2",
            date: "19920511152811.123",
            century: 20,
            decade: 90,
            quarter: 2,
            weekday: 1,
            millisecond: 123,
            microsecond: 123000,
            nanosecond: 123000000,
            timestamp: 705598091,
            timestampWithSecond: 705598091,
            timestampWithMillisecond: 705598091123,
            timestampWithMicrosecond: 705598091123000,
            timestampWithNanosecond: 705598091123000000,
            year: 1992,
            month: 05,
            day: 11,
            hour: 15,
            minute: 28,
            second: 11,
        },
    }

    for _, td := range tests {
        d := Parse(td.date).WithTimezone(UTC)

        eq(d.Century(), td.century, "failed DatetimeAll Century, index " + td.index)
        eq(d.Decade(), td.decade, "failed DatetimeAll Decade, index " + td.index)
        eq(d.Year(), td.year, "failed DatetimeAll Year, index " + td.index)
        eq(d.Quarter(), td.quarter, "failed DatetimeAll Quarter, index " + td.index)
        eq(d.Month(), td.month, "failed DatetimeAll Month, index " + td.index)
        eq(d.Weekday(), td.weekday, "failed DatetimeAll Weekday, index " + td.index)
        eq(d.Day(), td.day, "failed DatetimeAll Day, index " + td.index)
        eq(d.Hour(), td.hour, "failed DatetimeAll Hour, index " + td.index)
        eq(d.Minute(), td.minute, "failed DatetimeAll Minute, index " + td.index)
        eq(d.Second(), td.second, "failed DatetimeAll Second, index " + td.index)

        eq(d.Millisecond(), td.millisecond, "failed DatetimeAll Millisecond, index " + td.index)
        eq(d.Microsecond(), td.microsecond, "failed DatetimeAll Microsecond, index " + td.index)
        eq(d.Nanosecond(), td.nanosecond, "failed DatetimeAll Nanosecond, index " + td.index)

        eq(d.Timestamp(), td.timestamp, "failed DatetimeAll Timestamp, index " + td.index)
        eq(d.TimestampWithSecond(), td.timestampWithSecond, "failed DatetimeAll TimestampWithSecond, index " + td.index)
        eq(d.TimestampWithMillisecond(), td.timestampWithMillisecond, "failed DatetimeAll TimestampWithMillisecond, index " + td.index)
        eq(d.TimestampWithMicrosecond(), td.timestampWithMicrosecond, "failed DatetimeAll TimestampWithMicrosecond, index " + td.index)
        eq(d.TimestampWithNanosecond(), td.timestampWithNanosecond, "failed DatetimeAll TimestampWithNanosecond, index " + td.index)
    }
}
