package datebin

import (
	"testing"
)

func Test_Date(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index            string
		date             string
		year, month, day int
	}{
		{
			index: "index-1",
			date:  "2025-06-07 06:35:23",
			year:  2025,
			month: 06,
			day:   07,
		},
		{
			index: "index-2",
			date:  "1992-05-11 15:28:11",
			year:  1992,
			month: 05,
			day:   11,
		},
	}

	for _, td := range tests {
		year, month, day := Parse(td.date).WithTimezone(UTC).Date()

		eq(year, td.year, "failed Date year, index "+td.index)
		eq(month, td.month, "failed Date month, index "+td.index)
		eq(day, td.day, "failed Date day, index "+td.index)
	}
}

func Test_Time(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index                string
		date                 string
		hour, minute, second int
	}{
		{
			index:  "index-1",
			date:   "2025-06-07 06:35:23",
			hour:   06,
			minute: 35,
			second: 23,
		},
		{
			index:  "index-2",
			date:   "1992-05-11 15:28:11",
			hour:   15,
			minute: 28,
			second: 11,
		},
	}

	for _, td := range tests {
		hour, minute, second := Parse(td.date).WithTimezone(UTC).Time()

		eq(hour, td.hour, "failed Time hour, index "+td.index)
		eq(minute, td.minute, "failed Time minute, index "+td.index)
		eq(second, td.second, "failed Time second, index "+td.index)
	}
}

func Test_Datetime(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index                                  string
		date                                   string
		year, month, day, hour, minute, second int
	}{
		{
			index:  "index-1",
			date:   "2025-06-07 06:35:23",
			year:   2025,
			month:  06,
			day:    07,
			hour:   06,
			minute: 35,
			second: 23,
		},
		{
			index:  "index-2",
			date:   "1992-05-11 15:28:11",
			year:   1992,
			month:  05,
			day:    11,
			hour:   15,
			minute: 28,
			second: 11,
		},
	}

	for _, td := range tests {
		year, month, day, hour, minute, second := Parse(td.date).WithTimezone(UTC).Datetime()

		eq(year, td.year, "failed Datetime year, index "+td.index)
		eq(month, td.month, "failed Datetime month, index "+td.index)
		eq(day, td.day, "failed Datetime day, index "+td.index)
		eq(hour, td.hour, "failed Datetime hour, index "+td.index)
		eq(minute, td.minute, "failed Datetime minute, index "+td.index)
		eq(second, td.second, "failed Datetime second, index "+td.index)
	}
}

func Test_DatetimeWithNanosecond(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index                                              string
		date                                               string
		year, month, day, hour, minute, second, nanosecond int
	}{
		{
			index:      "index-1",
			date:       "2025-06-07 06:35:23",
			year:       2025,
			month:      06,
			day:        07,
			hour:       06,
			minute:     35,
			second:     23,
			nanosecond: 0,
		},
		{
			index:      "index-2",
			date:       "19920511152811.000000123",
			year:       1992,
			month:      05,
			day:        11,
			hour:       15,
			minute:     28,
			second:     11,
			nanosecond: 123,
		},
	}

	for _, td := range tests {
		year, month, day, hour, minute, second, nanosecond := Parse(td.date).WithTimezone(UTC).DatetimeWithNanosecond()

		eq(year, td.year, "failed DatetimeWithNanosecond year, index "+td.index)
		eq(month, td.month, "failed DatetimeWithNanosecond month, index "+td.index)
		eq(day, td.day, "failed DatetimeWithNanosecond day, index "+td.index)
		eq(hour, td.hour, "failed DatetimeWithNanosecond hour, index "+td.index)
		eq(minute, td.minute, "failed DatetimeWithNanosecond minute, index "+td.index)
		eq(second, td.second, "failed DatetimeWithNanosecond second, index "+td.index)
		eq(nanosecond, td.nanosecond, "failed DatetimeWithNanosecond nanosecond, index "+td.index)
	}
}

func Test_DatetimeWithMicrosecond(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index                                               string
		date                                                string
		year, month, day, hour, minute, second, microsecond int
	}{
		{
			index:       "index-1",
			date:        "2025-06-07 06:35:23",
			year:        2025,
			month:       06,
			day:         07,
			hour:        06,
			minute:      35,
			second:      23,
			microsecond: 0,
		},
		{
			index:       "index-2",
			date:        "19920511152811.000123",
			year:        1992,
			month:       05,
			day:         11,
			hour:        15,
			minute:      28,
			second:      11,
			microsecond: 123,
		},
	}

	for _, td := range tests {
		year, month, day, hour, minute, second, microsecond := Parse(td.date).WithTimezone(UTC).DatetimeWithMicrosecond()

		eq(year, td.year, "failed DatetimeWithMicrosecond year, index "+td.index)
		eq(month, td.month, "failed DatetimeWithMicrosecond month, index "+td.index)
		eq(day, td.day, "failed DatetimeWithMicrosecond day, index "+td.index)
		eq(hour, td.hour, "failed DatetimeWithMicrosecond hour, index "+td.index)
		eq(minute, td.minute, "failed DatetimeWithMicrosecond minute, index "+td.index)
		eq(second, td.second, "failed DatetimeWithMicrosecond second, index "+td.index)
		eq(microsecond, td.microsecond, "failed DatetimeWithMicrosecond microsecond, index "+td.index)
	}
}

func Test_DatetimeWithMillisecond(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index                                               string
		date                                                string
		year, month, day, hour, minute, second, millisecond int
	}{
		{
			index:       "index-1",
			date:        "2025-06-07 06:35:23",
			year:        2025,
			month:       06,
			day:         07,
			hour:        06,
			minute:      35,
			second:      23,
			millisecond: 0,
		},
		{
			index:       "index-2",
			date:        "19920511152811.123",
			year:        1992,
			month:       05,
			day:         11,
			hour:        15,
			minute:      28,
			second:      11,
			millisecond: 123,
		},
	}

	for _, td := range tests {
		year, month, day, hour, minute, second, millisecond := Parse(td.date).WithTimezone(UTC).DatetimeWithMillisecond()

		eq(year, td.year, "failed DatetimeWithMillisecond year, index "+td.index)
		eq(month, td.month, "failed DatetimeWithMillisecond month, index "+td.index)
		eq(day, td.day, "failed DatetimeWithMillisecond day, index "+td.index)
		eq(hour, td.hour, "failed DatetimeWithMillisecond hour, index "+td.index)
		eq(minute, td.minute, "failed DatetimeWithMillisecond minute, index "+td.index)
		eq(second, td.second, "failed DatetimeWithMillisecond second, index "+td.index)
		eq(millisecond, td.millisecond, "failed DatetimeWithMillisecond millisecond, index "+td.index)
	}
}
