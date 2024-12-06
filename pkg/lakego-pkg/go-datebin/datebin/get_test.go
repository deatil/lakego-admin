package datebin

import (
	"testing"
	"time"
)

func Test_Now(t *testing.T) {
	eq := assertEqualT(t)

	actual1 := Now().ToDatetimeString()
	expected1 := time.Now().Format(DatetimeFormat)

	eq(actual1, expected1, "failed now time is error")

	actual2 := Now(Local).ToDatetimeString()
	expected2 := time.Now().In(time.Local).Format(DatetimeFormat)

	eq(actual2, expected2, "failed now time Local is error")
}

func Test_Today(t *testing.T) {
	eq := assertEqualT(t)

	actual1 := Today().ToDateString()
	expected1 := time.Now().Format(DateFormat)

	eq(actual1, expected1, "failed Today error")

	actual2 := Today(Local).ToDateString()
	expected2 := time.Now().In(time.Local).Format(DateFormat)

	eq(actual2, expected2, "failed Today2 error")
}

func Test_Tomorrow(t *testing.T) {
	eq := assertEqualT(t)

	actual1 := Tomorrow().ToDateString()
	expected1 := time.Now().AddDate(0, 0, 1).Format(DateFormat)

	eq(actual1, expected1, "failed Tomorrow error")

	actual2 := Tomorrow(Local).ToDateString()
	expected2 := time.Now().In(time.Local).AddDate(0, 0, 1).Format(DateFormat)

	eq(actual2, expected2, "failed Tomorrow2 error")
}

func Test_Yesterday(t *testing.T) {
	eq := assertEqualT(t)

	actual1 := Yesterday().ToDateString()
	expected1 := time.Now().AddDate(0, 0, -1).Format(DateFormat)

	eq(actual1, expected1, "failed Yesterday error")

	actual2 := Yesterday(Local).ToDateString()
	expected2 := time.Now().In(time.Local).AddDate(0, 0, -1).Format(DateFormat)

	eq(actual2, expected2, "failed Yesterday2 error")
}

func Test_Today2(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date1 string
		check string
	}{
		{
			index: "index-1",
			date1: "2024-06-06 21:15:12",
			check: "2024-06-06 00:00:00",
		},
		{
			index: "index-2",
			date1: "2024-06-05 21:15:12",
			check: "2024-06-05 00:00:00",
		},
	}

	for _, td := range tests {
		dataTt := Parse(td.date1).ToDatetimeString(UTC)
		check := Parse(td.date1).Today(UTC).ToDatetimeString()

		eq(dataTt, td.date1, "failed Today2 date1, index "+td.index)
		eq(check, td.check, "failed Today2, index "+td.index)
	}
}

func Test_Tomorrow2(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date1 string
		check string
	}{
		{
			index: "index-1",
			date1: "2024-06-06 21:15:12",
			check: "2024-06-07 00:00:00",
		},
		{
			index: "index-2",
			date1: "2024-06-05 21:15:12",
			check: "2024-06-06 00:00:00",
		},
	}

	for _, td := range tests {
		dataTt := Parse(td.date1).ToDatetimeString(UTC)
		check := Parse(td.date1).Tomorrow(UTC).ToDatetimeString()

		eq(dataTt, td.date1, "failed Tomorrow2 date1, index "+td.index)
		eq(check, td.check, "failed Tomorrow2, index "+td.index)
	}
}

func Test_Yesterday2(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date1 string
		check string
	}{
		{
			index: "index-1",
			date1: "2024-06-06 21:15:12",
			check: "2024-06-05 00:00:00",
		},
		{
			index: "index-2",
			date1: "2024-06-12 21:15:12",
			check: "2024-06-11 00:00:00",
		},
	}

	for _, td := range tests {
		dataTt := Parse(td.date1).ToDatetimeString(UTC)
		check := Parse(td.date1).Yesterday(UTC).ToDatetimeString()

		eq(dataTt, td.date1, "failed Yesterday2 date1, index "+td.index)
		eq(check, td.check, "failed Yesterday2, index "+td.index)
	}
}

func Test_Min(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date1 string
		date2 string
		check string
	}{
		{
			index: "index-1",
			date1: "2024-06-06 21:15:12",
			date2: "2024-06-12 22:15:12",
			check: "2024-06-06 21:15:12",
		},
		{
			index: "index-2",
			date1: "2024-06-13 21:15:12",
			date2: "2024-06-05 10:15:12",
			check: "2024-06-05 10:15:12",
		},
	}

	for _, td := range tests {
		check := Parse(td.date1).Min(Parse(td.date2)).ToDatetimeString(UTC)

		eq(check, td.check, "failed Min, index "+td.index)
	}
}

func Test_Max(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date1 string
		date2 string
		check string
	}{
		{
			index: "index-1",
			date1: "2024-06-06 21:15:12",
			date2: "2024-06-12 22:15:12",
			check: "2024-06-12 22:15:12",
		},
		{
			index: "index-2",
			date1: "2024-06-13 21:15:12",
			date2: "2024-06-05 10:15:12",
			check: "2024-06-13 21:15:12",
		},
	}

	for _, td := range tests {
		check := Parse(td.date1).Max(Parse(td.date2)).ToDatetimeString(UTC)

		eq(check, td.check, "failed Max, index "+td.index)
	}
}

func Test_Avg(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date1 string
		date2 string
		check string
	}{
		{
			index: "index-1",
			date1: "2024-06-06 21:15:12",
			date2: "2024-06-12 22:15:12",
			check: "2024-06-09 21:45:12",
		},
		{
			index: "index-2",
			date1: "2024-06-13 21:15:12",
			date2: "2024-06-05 10:15:12",
			check: "2024-06-09 15:45:12",
		},
	}

	for _, td := range tests {
		check := Parse(td.date1).Avg(Parse(td.date2)).ToDatetimeString(UTC)

		eq(check, td.check, "failed Avg, index "+td.index)
	}
}

func Test_Closest(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  string
		date1 string
		date2 string
		check string
	}{
		{
			index: "index-1",
			date:  "2024-06-15 21:11:09",
			date1: "2024-06-06 21:15:12",
			date2: "2024-06-12 22:15:12",
			check: "2024-06-12 22:15:12",
		},
		{
			index: "index-2",
			date:  "2024-06-06 21:15:12",
			date1: "2024-06-13 21:15:12",
			date2: "2024-06-05 10:15:12",
			check: "2024-06-05 10:15:12",
		},
	}

	for _, td := range tests {
		check := Parse(td.date).
			Closest(Parse(td.date1), Parse(td.date2)).
			ToDatetimeString(UTC)

		eq(check, td.check, "failed Closest, index "+td.index)
	}
}

func Test_Farthest(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  string
		date1 string
		date2 string
		check string
	}{
		{
			index: "index-1",
			date:  "2024-06-15 21:11:09",
			date1: "2024-06-06 21:15:12",
			date2: "2024-06-12 22:15:12",
			check: "2024-06-06 21:15:12",
		},
		{
			index: "index-2",
			date:  "2024-06-06 21:15:12",
			date1: "2024-06-13 21:15:12",
			date2: "2024-06-05 10:15:12",
			check: "2024-06-13 21:15:12",
		},
	}

	for _, td := range tests {
		check := Parse(td.date).
			Farthest(Parse(td.date1), Parse(td.date2)).
			ToDatetimeString(UTC)

		eq(check, td.check, "failed Farthest, index "+td.index)
	}
}

func Test_Age(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date1 string
		check int
	}{
		{
			index: "index-1",
			date1: "2027-06-06 21:15:12",
			check: -2,
		},
		{
			index: "index-2",
			date1: "2013-10-12 21:15:12",
			check: 11,
		},
		{
			index: "index-2",
			date1: "2024-10-12 21:15:12",
			check: 0,
		},
	}

	for _, td := range tests {
		check := Parse(td.date1).Age()

		eq(check, td.check, "failed Age, index "+td.index)
	}
}

func Test_Round(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index    string
		date1    string
		duration string
		check    string
	}{
		{
			index:    "index-1",
			date1:    "2025-06-06 21:15:12",
			duration: "1h15m",
			check:    "2025-06-06 20:45:00",
		},
		{
			index:    "index-2",
			date1:    "2012-10-12 21:15:12",
			duration: "2h35m",
			check:    "2012-10-12 20:00:00",
		},
	}

	for _, td := range tests {
		d, _ := time.ParseDuration(td.duration)

		check := Parse(td.date1).
			Round(d).
			ToDatetimeString(UTC)

		eq(check, td.check, "failed Round, index "+td.index)
	}
}

func Test_Truncate(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index    string
		date1    string
		duration string
		check    string
	}{
		{
			index:    "index-1",
			date1:    "2025-06-07 06:35:23",
			duration: "1h15m",
			check:    "2025-06-07 05:30:00",
		},
		{
			index:    "index-2",
			date1:    "2012-10-12 21:15:12",
			duration: "2h35m",
			check:    "2012-10-12 20:00:00",
		},
	}

	for _, td := range tests {
		d, _ := time.ParseDuration(td.duration)

		check := Parse(td.date1).
			Truncate(d).
			ToDatetimeString(UTC)

		eq(check, td.check, "failed Truncate, index "+td.index)
	}
}
