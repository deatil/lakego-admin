package datebin

import (
	"testing"
	"time"
)

func Test_FromStdTime(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index  string
		layout string
		date   string
		check  string
	}{
		{
			index:  "index-1",
			layout: "2006-01-02 15:04:05",
			date:   "2024-01-03 21:15:12",
			check:  "2024-01-03 21:15:12",
		},
		{
			index:  "index-2",
			layout: "2006-01-02 15:04:05",
			date:   "2023-01-03 21:15:12",
			check:  "2023-01-03 21:15:12",
		},
	}

	for _, td := range tests {
		tt, err := time.ParseInLocation(td.layout, td.date, time.Local)
		if err != nil {
			t.Fatal(err)
		}

		parseTt := FromStdTime(tt).ToDatetimeString()

		eq(parseTt, td.check, "failed FromStdTime, index "+td.index)
	}
}

func Test_FromStdUnix(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index  string
		layout string
		date   string
		check  string
	}{
		{
			index:  "index-1",
			layout: "2006-01-02 15:04:05.999",
			date:   "2024-01-03 21:15:12.222",
			check:  "2024-01-03 21:15:12.222",
		},
		{
			index:  "index-2",
			layout: "2006-01-02 15:04:05.999",
			date:   "2023-01-05 21:15:12.222",
			check:  "2023-01-05 21:15:12.222",
		},
	}

	for _, td := range tests {
		tt, err := time.ParseInLocation(td.layout, td.date, time.Local)
		if err != nil {
			t.Fatal(err)
		}

		parseTt := FromStdUnix(tt.Unix(), int64(tt.Nanosecond())).ToLayoutString(DatetimeMilliFormat)

		eq(parseTt, td.check, "failed FromStdUnix, index "+td.index)
	}
}

func Test_FromTimestamp(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index  string
		layout string
		date   string
		check  string
	}{
		{
			index:  "index-1",
			layout: "2006-01-02 15:04:05",
			date:   "2024-01-03 21:15:12",
			check:  "2024-01-03 21:15:12",
		},
		{
			index:  "index-2",
			layout: "2006-01-02 15:04:05",
			date:   "2023-01-05 21:15:12",
			check:  "2023-01-05 21:15:12",
		},
	}

	for _, td := range tests {
		tt, err := time.ParseInLocation(td.layout, td.date, time.Local)
		if err != nil {
			t.Fatal(err)
		}

		parseTt := FromTimestamp(tt.Unix()).ToDatetimeString()

		eq(parseTt, td.check, "failed FromTimestamp, index "+td.index)
	}
}

func Test_FromDatetimeWithNanosecond(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index                                              string
		year, month, day, hour, minute, second, nanosecond int
		check                                              string
	}{
		{
			index:      "index-1",
			year:       2024,
			month:      01,
			day:        03,
			hour:       21,
			minute:     15,
			second:     12,
			nanosecond: 1,
			check:      "2024-01-03 21:15:12.000000001",
		},
		{
			index:      "index-2",
			year:       2023,
			month:      01,
			day:        05,
			hour:       21,
			minute:     15,
			second:     12,
			nanosecond: 120,
			check:      "2023-01-05 21:15:12.00000012",
		},
	}

	for _, td := range tests {
		parseTt := FromDatetimeWithNanosecond(
			td.year, td.month, td.day,
			td.hour, td.minute, td.second, td.nanosecond,
		).
			ToLayoutString(DatetimeNanoFormat)

		eq(parseTt, td.check, "failed FromDatetimeWithNanosecond, index "+td.index)
	}
}

func Test_FromDatetimeWithMicrosecond(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index                                               string
		year, month, day, hour, minute, second, microsecond int
		check                                               string
	}{
		{
			index:       "index-1",
			year:        2024,
			month:       01,
			day:         03,
			hour:        21,
			minute:      15,
			second:      12,
			microsecond: 1,
			check:       "2024-01-03 21:15:12.000001",
		},
		{
			index:       "index-2",
			year:        2023,
			month:       01,
			day:         05,
			hour:        21,
			minute:      15,
			second:      12,
			microsecond: 120,
			check:       "2023-01-05 21:15:12.00012",
		},
	}

	for _, td := range tests {
		parseTt := FromDatetimeWithMicrosecond(
			td.year, td.month, td.day,
			td.hour, td.minute, td.second, td.microsecond,
		).
			ToLayoutString(DatetimeNanoFormat)

		eq(parseTt, td.check, "failed FromDatetimeWithMicrosecond, index "+td.index)
	}
}

func Test_FromDatetimeWithMillisecond(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index                                               string
		year, month, day, hour, minute, second, millisecond int
		check                                               string
	}{
		{
			index:       "index-1",
			year:        2024,
			month:       01,
			day:         03,
			hour:        21,
			minute:      15,
			second:      12,
			millisecond: 1,
			check:       "2024-01-03 21:15:12.001",
		},
		{
			index:       "index-2",
			year:        2023,
			month:       01,
			day:         05,
			hour:        21,
			minute:      15,
			second:      12,
			millisecond: 120,
			check:       "2023-01-05 21:15:12.12",
		},
	}

	for _, td := range tests {
		parseTt := FromDatetimeWithMillisecond(
			td.year, td.month, td.day,
			td.hour, td.minute, td.second, td.millisecond,
		).
			ToLayoutString(DatetimeNanoFormat)

		eq(parseTt, td.check, "failed FromDatetimeWithMillisecond, index "+td.index)
	}
}

func Test_FromDatetime(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index                                  string
		year, month, day, hour, minute, second int
		check                                  string
	}{
		{
			index:  "index-1",
			year:   2024,
			month:  01,
			day:    03,
			hour:   21,
			minute: 15,
			second: 12,
			check:  "2024-01-03 21:15:12",
		},
		{
			index:  "index-2",
			year:   2023,
			month:  01,
			day:    05,
			hour:   21,
			minute: 15,
			second: 12,
			check:  "2023-01-05 21:15:12",
		},
	}

	for _, td := range tests {
		parseTt := FromDatetime(
			td.year, td.month, td.day,
			td.hour, td.minute, td.second,
		).
			ToDatetimeString()

		eq(parseTt, td.check, "failed FromDatetime, index "+td.index)
	}
}

func Test_FromDate(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index            string
		year, month, day int
		check            string
	}{
		{
			index: "index-1",
			year:  2024,
			month: 01,
			day:   03,
			check: "2024-01-03 00:00:00",
		},
		{
			index: "index-2",
			year:  2023,
			month: 01,
			day:   05,
			check: "2023-01-05 00:00:00",
		},
	}

	for _, td := range tests {
		parseTt := FromDate(
			td.year, td.month, td.day,
		).
			ToDatetimeString()

		eq(parseTt, td.check, "failed FromDate, index "+td.index)
	}
}

func Test_FromTime(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index                string
		hour, minute, second int
		check                string
	}{
		{
			index:  "index-1",
			hour:   21,
			minute: 15,
			second: 12,
			check:  "21:15:12",
		},
		{
			index:  "index-2",
			hour:   21,
			minute: 15,
			second: 12,
			check:  "21:15:12",
		},
	}

	for _, td := range tests {
		pt := FromTime(td.hour, td.minute, td.second)

		parseTt := pt.ToTimeString()
		parseDate := pt.ToDateString()

		eq(parseTt, td.check, "failed FromTime, index "+td.index)
		eq(parseDate, time.Now().Local().Format(DateFormat), "failed FromTime ToDateString, index "+td.index)
	}
}
