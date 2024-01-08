package datebin

import (
	"testing"
)

func Test_IsMonday(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  string
		tz    string
		check bool
	}{
		{
			index: "index-1",
			date:  "",
			tz:    "EST",
			check: false,
		},
		{
			index: "index-2",
			date:  "2023-12-04 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-3",
			date:  "2021-03-05 21:15:12",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsMonday()

		eq(check, td.check, "failed IsMonday, index "+td.index)
	}
}

func Test_IsTuesday(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  string
		tz    string
		check bool
	}{
		{
			index: "index-1",
			date:  "",
			tz:    "EST",
			check: false,
		},
		{
			index: "index-2",
			date:  "2023-12-05 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-3",
			date:  "2021-03-05 21:15:12",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsTuesday()

		eq(check, td.check, "failed IsTuesday, index "+td.index)
	}
}

func Test_IsWednesday(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  string
		tz    string
		check bool
	}{
		{
			index: "index-1",
			date:  "",
			tz:    "EST",
			check: false,
		},
		{
			index: "index-2",
			date:  "2023-12-06 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-3",
			date:  "2021-03-05 21:15:12",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsWednesday()

		eq(check, td.check, "failed IsWednesday, index "+td.index)
	}
}

func Test_IsThursday(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  string
		tz    string
		check bool
	}{
		{
			index: "index-1",
			date:  "",
			tz:    "EST",
			check: false,
		},
		{
			index: "index-2",
			date:  "2023-12-07 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-3",
			date:  "2021-03-05 21:15:12",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsThursday()

		eq(check, td.check, "failed IsThursday, index "+td.index)
	}
}

func Test_IsFriday(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  string
		tz    string
		check bool
	}{
		{
			index: "index-1",
			date:  "",
			tz:    "EST",
			check: false,
		},
		{
			index: "index-2",
			date:  "2023-12-08 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-3",
			date:  "2021-03-01 21:15:12",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsFriday()

		eq(check, td.check, "failed IsFriday, index "+td.index)
	}
}

func Test_IsSaturday(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  string
		tz    string
		check bool
	}{
		{
			index: "index-1",
			date:  "",
			tz:    "EST",
			check: false,
		},
		{
			index: "index-2",
			date:  "2023-12-09 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-3",
			date:  "2021-03-01 21:15:12",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsSaturday()

		eq(check, td.check, "failed IsSaturday, index "+td.index)
	}
}

func Test_IsSunday(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  string
		tz    string
		check bool
	}{
		{
			index: "index-1",
			date:  "",
			tz:    "EST",
			check: false,
		},
		{
			index: "index-2",
			date:  "2023-12-10 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-3",
			date:  "2021-03-01 21:15:12",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsSunday()

		eq(check, td.check, "failed IsSunday, index "+td.index)
	}
}

func Test_IsWeekday(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  string
		tz    string
		check bool
	}{
		{
			index: "index-1",
			date:  "",
			tz:    "EST",
			check: false,
		},
		{
			index: "index-2",
			date:  "2023-12-07 12:00:00",
			tz:    "UTC",
			check: true,
		},
		{
			index: "index-3",
			date:  "2021-03-13 21:15:12",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsWeekday()

		eq(check, td.check, "failed IsWeekday, index "+td.index)
	}
}

func Test_IsWeekend(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  string
		tz    string
		check bool
	}{
		{
			index: "index-1",
			date:  "",
			tz:    "EST",
			check: false,
		},
		{
			index: "index-2",
			date:  "2023-12-10 12:00:00",
			tz:    "UTC",
			check: true,
		},
		{
			index: "index-3",
			date:  "2021-03-11 21:15:12",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsWeekend()

		eq(check, td.check, "failed IsWeekend, index "+td.index)
	}
}
