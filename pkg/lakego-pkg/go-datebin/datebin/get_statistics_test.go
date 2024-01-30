package datebin

import (
	"testing"
)

func Test_Statistics(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index       string
		date        string
		DaysInMonth int
		MonthOfYear int
		DayOfYear   int
		DayOfMonth  int
		DayOfWeek   int
		WeekOfYear  int
	}{
		{
			index:       "index-1",
			date:        "2025-06-07 06:35:23",
			DaysInMonth: 30,
			MonthOfYear: 6,
			DayOfYear:   158,
			DayOfMonth:  7,
			DayOfWeek:   6,
			WeekOfYear:  23,
		},
		{
			index:       "index-2",
			date:        "19920511152811.123",
			DaysInMonth: 31,
			MonthOfYear: 5,
			DayOfYear:   132,
			DayOfMonth:  11,
			DayOfWeek:   1,
			WeekOfYear:  20,
		},
		{
			index:       "index-3",
			date:        "",
			DaysInMonth: 0,
			MonthOfYear: 0,
			DayOfYear:   0,
			DayOfMonth:  0,
			DayOfWeek:   0,
			WeekOfYear:  0,
		},
		{
			index:       "index-4",
			date:        "0",
			DaysInMonth: 0,
			MonthOfYear: 0,
			DayOfYear:   0,
			DayOfMonth:  0,
			DayOfWeek:   0,
			WeekOfYear:  0,
		},
	}

	for _, td := range tests {
		d := Parse(td.date).SetTimezone(UTC)

		eq(d.DaysInMonth(), td.DaysInMonth, "failed Statistics DaysInMonth, index "+td.index)
		eq(d.MonthOfYear(), td.MonthOfYear, "failed Statistics MonthOfYear, index "+td.index)
		eq(d.DayOfYear(), td.DayOfYear, "failed Statistics DayOfYear, index "+td.index)
		eq(d.DayOfMonth(), td.DayOfMonth, "failed Statistics DayOfMonth, index "+td.index)
		eq(d.DayOfWeek(), td.DayOfWeek, "failed Statistics DayOfWeek, index "+td.index)
		eq(d.WeekOfYear(), td.WeekOfYear, "failed Statistics WeekOfYear, index "+td.index)
	}
}
