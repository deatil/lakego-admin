package datebin

import (
	"testing"
	"time"
)

func Test_NYearStart(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index  string
		layout string
		date   string
		year   int
		check  string
	}{
		{
			index:  "index-1",
			layout: "2006-01-02 15:04:05",
			date:   "2024-01-03 21:15:12",
			year:   25,
			check:  "2000-01-01 00:00:00",
		},
		{
			index:  "index-2",
			layout: "20060102150405",
			date:   "20240103211512",
			year:   35,
			check:  "1995-01-01 00:00:00",
		},
		{
			index:  "index-3",
			layout: "20060102150405",
			date:   "",
			year:   35,
			check:  "",
		},
	}

	for _, td := range tests {
		date := ParseWithLayout(td.date, td.layout).
			NYearStart(td.year).
			ToDatetimeString()

		eq(date, td.check, "failed NYearStart, index "+td.index)
	}
}

func Test_NYearEnd(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index  string
		layout string
		date   string
		year   int
		check  string
	}{
		{
			index:  "index-1",
			layout: "2006-01-02 15:04:05",
			date:   "2024-01-03 21:15:12",
			year:   25,
			check:  "2024-12-31 23:59:59",
		},
		{
			index:  "index-2",
			layout: "20060102150405",
			date:   "20240103211512",
			year:   35,
			check:  "2029-12-31 23:59:59",
		},
		{
			index:  "index-3",
			layout: "20060102150405",
			date:   "",
			year:   35,
			check:  "",
		},
	}

	for _, td := range tests {
		date := ParseWithLayout(td.date, td.layout).
			NYearEnd(td.year).
			ToDatetimeString()

		eq(date, td.check, "failed NYearEnd, index "+td.index)
	}
}

func Test_CenturyStart(t *testing.T) {
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
			check:  "2000-01-01 00:00:00",
		},
		{
			index:  "index-2",
			layout: "20060102150405",
			date:   "19350103211512",
			check:  "1900-01-01 00:00:00",
		},
		{
			index:  "index-3",
			layout: "20060102150405",
			date:   "",
			check:  "",
		},
	}

	for _, td := range tests {
		date := ParseWithLayout(td.date, td.layout).
			CenturyStart().
			ToDatetimeString()

		eq(date, td.check, "failed CenturyStart, index "+td.index)
	}
}

func Test_CenturyEnd(t *testing.T) {
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
			check:  "2099-12-31 23:59:59",
		},
		{
			index:  "index-2",
			layout: "20060102150405",
			date:   "19350103211512",
			check:  "1999-12-31 23:59:59",
		},
		{
			index:  "index-3",
			layout: "20060102150405",
			date:   "",
			check:  "",
		},
	}

	for _, td := range tests {
		date := ParseWithLayout(td.date, td.layout).
			CenturyEnd().
			ToDatetimeString()

		eq(date, td.check, "failed CenturyEnd, index "+td.index)
	}
}

func Test_DecadeStart(t *testing.T) {
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
			check:  "2020-01-01 00:00:00",
		},
		{
			index:  "index-2",
			layout: "20060102150405",
			date:   "19350103211512",
			check:  "1930-01-01 00:00:00",
		},
		{
			index:  "index-3",
			layout: "20060102150405",
			date:   "",
			check:  "",
		},
	}

	for _, td := range tests {
		date := ParseWithLayout(td.date, td.layout).
			DecadeStart().
			ToDatetimeString()

		eq(date, td.check, "failed DecadeStart, index "+td.index)
	}
}

func Test_DecadeEnd(t *testing.T) {
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
			check:  "2029-12-31 23:59:59",
		},
		{
			index:  "index-2",
			layout: "20060102150405",
			date:   "19350103211512",
			check:  "1939-12-31 23:59:59",
		},
		{
			index:  "index-3",
			layout: "20060102150405",
			date:   "",
			check:  "",
		},
	}

	for _, td := range tests {
		date := ParseWithLayout(td.date, td.layout).
			DecadeEnd().
			ToDatetimeString()

		eq(date, td.check, "failed DecadeEnd, index "+td.index)
	}
}

func Test_YearStart(t *testing.T) {
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
			date:   "2024-06-03 21:15:12",
			check:  "2024-01-01 00:00:00",
		},
		{
			index:  "index-2",
			layout: "20060102150405",
			date:   "19350903211512",
			check:  "1935-01-01 00:00:00",
		},
		{
			index:  "index-3",
			layout: "20060102150405",
			date:   "",
			check:  "",
		},
	}

	for _, td := range tests {
		date := ParseWithLayout(td.date, td.layout).
			YearStart().
			ToDatetimeString()

		eq(date, td.check, "failed YearStart, index "+td.index)
	}
}

func Test_YearEnd(t *testing.T) {
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
			date:   "2024-06-03 21:15:12",
			check:  "2024-12-31 23:59:59",
		},
		{
			index:  "index-2",
			layout: "20060102150405",
			date:   "19350903211512",
			check:  "1935-12-31 23:59:59",
		},
		{
			index:  "index-3",
			layout: "20060102150405",
			date:   "",
			check:  "",
		},
	}

	for _, td := range tests {
		date := ParseWithLayout(td.date, td.layout).
			YearEnd().
			ToDatetimeString()

		eq(date, td.check, "failed YearEnd, index "+td.index)
	}
}

func Test_SeasonStart(t *testing.T) {
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
			date:   "2024-07-03 21:15:12",
			check:  "2024-06-01 00:00:00",
		},
		{
			index:  "index-2",
			layout: "20060102150405",
			date:   "19351003211512",
			check:  "1935-09-01 00:00:00",
		},
		{
			index:  "index-3",
			layout: "20060102150405",
			date:   "",
			check:  "",
		},
	}

	for _, td := range tests {
		date := ParseWithLayout(td.date, td.layout).
			SeasonStart().
			ToDatetimeString()

		eq(date, td.check, "failed SeasonStart, index "+td.index)
	}
}

func Test_SeasonEnd(t *testing.T) {
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
			date:   "2024-07-03 21:15:12",
			check:  "2024-08-31 23:59:59",
		},
		{
			index:  "index-2",
			layout: "20060102150405",
			date:   "19351003211512",
			check:  "1935-11-30 23:59:59",
		},
		{
			index:  "index-3",
			layout: "20060102150405",
			date:   "",
			check:  "",
		},
	}

	for _, td := range tests {
		date := ParseWithLayout(td.date, td.layout).
			SeasonEnd().
			ToDatetimeString()

		eq(date, td.check, "failed SeasonEnd, index "+td.index)
	}
}

func Test_MonthStart(t *testing.T) {
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
			date:   "2024-07-03 21:15:12",
			check:  "2024-07-01 00:00:00",
		},
		{
			index:  "index-2",
			layout: "20060102150405",
			date:   "19351003211512",
			check:  "1935-10-01 00:00:00",
		},
		{
			index:  "index-3",
			layout: "20060102150405",
			date:   "",
			check:  "",
		},
	}

	for _, td := range tests {
		date := ParseWithLayout(td.date, td.layout).
			MonthStart().
			ToDatetimeString()

		eq(date, td.check, "failed MonthStart, index "+td.index)
	}
}

func Test_MonthEnd(t *testing.T) {
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
			date:   "2024-07-03 21:15:12",
			check:  "2024-07-31 23:59:59",
		},
		{
			index:  "index-2",
			layout: "20060102150405",
			date:   "19351003211512",
			check:  "1935-10-31 23:59:59",
		},
		{
			index:  "index-3",
			layout: "20060102150405",
			date:   "",
			check:  "",
		},
	}

	for _, td := range tests {
		date := ParseWithLayout(td.date, td.layout).
			MonthEnd().
			ToDatetimeString()

		eq(date, td.check, "failed MonthEnd, index "+td.index)
	}
}

func Test_WeekStart(t *testing.T) {
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
			date:   "2024-07-03 21:15:12",
			check:  "2024-07-01 00:00:00",
		},
		{
			index:  "index-2",
			layout: "20060102150405",
			date:   "19351003211512",
			check:  "1935-09-30 00:00:00",
		},
		{
			index:  "index-3",
			layout: "20060102150405",
			date:   "",
			check:  "",
		},
	}

	for _, td := range tests {
		date := ParseWithLayout(td.date, td.layout).
			WeekStart().
			ToDatetimeString()

		eq(date, td.check, "failed WeekStart, index "+td.index)
	}
}

func Test_WeekEnd(t *testing.T) {
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
			date:   "2024-07-03 21:15:12",
			check:  "2024-07-07 23:59:59",
		},
		{
			index:  "index-2",
			layout: "20060102150405",
			date:   "19351003211512",
			check:  "1935-10-06 23:59:59",
		},
		{
			index:  "index-3",
			layout: "20060102150405",
			date:   "",
			check:  "",
		},
	}

	for _, td := range tests {
		date := ParseWithLayout(td.date, td.layout).
			WeekEnd().
			ToDatetimeString()

		eq(date, td.check, "failed WeekEnd, index "+td.index)
	}
}

func Test_DayStart(t *testing.T) {
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
			date:   "2024-07-03 21:15:12",
			check:  "2024-07-03 00:00:00",
		},
		{
			index:  "index-2",
			layout: "20060102150405",
			date:   "19351003211512",
			check:  "1935-10-03 00:00:00",
		},
		{
			index:  "index-3",
			layout: "20060102150405",
			date:   "",
			check:  "",
		},
	}

	for _, td := range tests {
		date := ParseWithLayout(td.date, td.layout).
			DayStart().
			ToDatetimeString()

		eq(date, td.check, "failed DayStart, index "+td.index)
	}
}

func Test_DayEnd(t *testing.T) {
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
			date:   "2024-07-03 21:15:12",
			check:  "2024-07-03 23:59:59",
		},
		{
			index:  "index-2",
			layout: "20060102150405",
			date:   "19351003211512",
			check:  "1935-10-03 23:59:59",
		},
		{
			index:  "index-3",
			layout: "20060102150405",
			date:   "",
			check:  "",
		},
	}

	for _, td := range tests {
		date := ParseWithLayout(td.date, td.layout).
			DayEnd().
			ToDatetimeString()

		eq(date, td.check, "failed DayEnd, index "+td.index)
	}
}

func Test_HourStart(t *testing.T) {
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
			date:   "2024-07-03 21:15:12",
			check:  "2024-07-03 21:00:00",
		},
		{
			index:  "index-2",
			layout: "20060102150405",
			date:   "19351003201512",
			check:  "1935-10-03 20:00:00",
		},
		{
			index:  "index-3",
			layout: "20060102150405",
			date:   "",
			check:  "",
		},
	}

	for _, td := range tests {
		date := ParseWithLayout(td.date, td.layout).
			HourStart().
			ToDatetimeString()

		eq(date, td.check, "failed HourStart, index "+td.index)
	}
}

func Test_HourEnd(t *testing.T) {
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
			date:   "2024-07-03 21:15:12",
			check:  "2024-07-03 21:59:59",
		},
		{
			index:  "index-2",
			layout: "20060102150405",
			date:   "19351003201512",
			check:  "1935-10-03 20:59:59",
		},
		{
			index:  "index-3",
			layout: "20060102150405",
			date:   "",
			check:  "",
		},
	}

	for _, td := range tests {
		date := ParseWithLayout(td.date, td.layout).
			HourEnd().
			ToDatetimeString()

		eq(date, td.check, "failed HourEnd, index "+td.index)
	}
}

func Test_MinuteStart(t *testing.T) {
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
			date:   "2024-07-03 21:15:12",
			check:  "2024-07-03 21:15:00",
		},
		{
			index:  "index-2",
			layout: "20060102150405",
			date:   "19351003201552",
			check:  "1935-10-03 20:15:00",
		},
		{
			index:  "index-3",
			layout: "20060102150405",
			date:   "",
			check:  "",
		},
	}

	for _, td := range tests {
		date := ParseWithLayout(td.date, td.layout).
			MinuteStart().
			ToDatetimeString()

		eq(date, td.check, "failed MinuteStart, index "+td.index)
	}
}

func Test_MinuteEnd(t *testing.T) {
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
			date:   "2024-07-03 21:15:12",
			check:  "2024-07-03 21:15:59",
		},
		{
			index:  "index-2",
			layout: "20060102150405",
			date:   "19351003201552",
			check:  "1935-10-03 20:15:59",
		},
		{
			index:  "index-3",
			layout: "20060102150405",
			date:   "",
			check:  "",
		},
	}

	for _, td := range tests {
		date := ParseWithLayout(td.date, td.layout).
			MinuteEnd().
			ToDatetimeString()

		eq(date, td.check, "failed MinuteEnd, index "+td.index)
	}
}

func Test_SecondStart(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index  string
		layout string
		date   string
		check  string
	}{
		{
			index:  "index-1",
			layout: DatetimeNanoFormat,
			date:   "2024-07-03 21:15:12.199359999",
			check:  "2024-07-03 21:15:12",
		},
		{
			index:  "index-2",
			layout: ShortDatetimeNanoFormat,
			date:   "19351003201552.219999999",
			check:  "1935-10-03 20:15:52",
		},
		{
			index:  "index-3",
			layout: "20060102150405",
			date:   "",
			check:  "",
		},
	}

	for _, td := range tests {
		date := ParseWithLayout(td.date, td.layout).
			SecondStart().
			ToLayoutString(DatetimeMilliFormat)

		eq(date, td.check, "failed SecondStart, index "+td.index)
	}
}

func Test_SecondEnd(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index  string
		layout string
		date   string
		check  string
	}{
		{
			index:  "index-1",
			layout: DatetimeNanoFormat,
			date:   "2024-07-03 21:15:12.199359999",
			check:  "2024-07-03 21:15:12.999999999",
		},
		{
			index:  "index-2",
			layout: ShortDatetimeNanoFormat,
			date:   "19351003201552.219999999",
			check:  "1935-10-03 20:15:52.999999999",
		},
		{
			index:  "index-3",
			layout: ShortDatetimeNanoFormat,
			date:   "",
			check:  "",
		},
	}

	for _, td := range tests {
		date := ParseWithLayout(td.date, td.layout).
			SecondEnd().
			ToLayoutString(DatetimeNanoFormat)

		eq(date, td.check, "failed SecondEnd, index "+td.index)
	}
}

func Test_DayOfWeekDates(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  string
		day   time.Weekday
		check []string
	}{
		{
			index: "index-1",
			date:  "2024-07-03 21:15:12",
			day:   time.Wednesday,
			check: []string{
				"2024-07-03 00:00:00",
				"2024-07-10 00:00:00",
				"2024-07-17 00:00:00",
				"2024-07-24 00:00:00",
				"2024-07-31 00:00:00",
			},
		},
		{
			index: "index-2",
			date:  "2015-07-03 13:22:13",
			day:   time.Saturday,
			check: []string{
				"2015-07-04 00:00:00",
				"2015-07-11 00:00:00",
				"2015-07-18 00:00:00",
				"2015-07-25 00:00:00",
			},
		},
	}

	for _, td := range tests {
		dates := Parse(td.date, UTC).DayOfWeekDates(td.day)

		res := make([]string, 0)
		for _, tt := range dates {
			res = append(res, tt.ToDatetimeString(UTC))
		}

		eq(res, td.check, "failed DayOfWeekDates, index "+td.index)
	}

}

func Test_StartAndEndOfWeeksOfMonth(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  string
		check [][]string
	}{
		{
			index: "index-1",
			date:  "2023-09-03 21:15:12",
			check: [][]string{
				{"2023-08-28 00:00:00", "2023-09-03 23:59:59"},
				{"2023-09-04 00:00:00", "2023-09-10 23:59:59"},
				{"2023-09-11 00:00:00", "2023-09-17 23:59:59"},
				{"2023-09-18 00:00:00", "2023-09-24 23:59:59"},
				{"2023-09-25 00:00:00", "2023-09-30 23:59:59"},
			},
		},
		{
			index: "index-2",
			date:  "2015-07-03 13:22:13",
			check: [][]string{
				{"2015-06-29 00:00:00", "2015-07-05 23:59:59"},
				{"2015-07-06 00:00:00", "2015-07-12 23:59:59"},
				{"2015-07-13 00:00:00", "2015-07-19 23:59:59"},
				{"2015-07-20 00:00:00", "2015-07-26 23:59:59"},
				{"2015-07-27 00:00:00", "2015-07-31 23:59:59"},
			},
		},
	}

	for _, td := range tests {
		dates := Parse(td.date, UTC).StartAndEndOfWeeksOfMonth()

		res := make([][]string, 0)
		for _, tt := range dates {
			res = append(res, []string{
				tt.Start.ToDatetimeString(UTC),
				tt.End.ToDatetimeString(UTC),
			})
		}

		eq(res, td.check, "failed StartAndEndOfWeeksOfMonth, index "+td.index)
	}

}
