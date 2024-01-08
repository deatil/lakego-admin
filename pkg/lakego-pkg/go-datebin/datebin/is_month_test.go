package datebin

import (
	"testing"
)

func Test_IsSpring(t *testing.T) {
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
			date:  "2024-03-01 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-3",
			date:  "2021-06-05 21:15:12",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsSpring()

		eq(check, td.check, "failed IsSpring, index "+td.index)
	}
}

func Test_IsSummer(t *testing.T) {
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
			date:  "2024-07-01 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-3",
			date:  "2021-02-05 21:15:12",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsSummer()

		eq(check, td.check, "failed IsSummer, index "+td.index)
	}
}

func Test_IsAutumn(t *testing.T) {
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
			date:  "2024-09-01 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-3",
			date:  "2021-02-05 21:15:12",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsAutumn()

		eq(check, td.check, "failed IsAutumn, index "+td.index)
	}
}

func Test_IsWinter(t *testing.T) {
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
			date:  "2024-01-01 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-3",
			date:  "2021-05-05 21:15:12",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsWinter()

		eq(check, td.check, "failed IsWinter, index "+td.index)
	}
}

func Test_IsJanuary(t *testing.T) {
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
			date:  "2024-01-01 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-3",
			date:  "2021-05-05 21:15:12",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsJanuary()

		eq(check, td.check, "failed IsJanuary, index "+td.index)
	}
}

func Test_IsFebruary(t *testing.T) {
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
			date:  "2023-02-01 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-3",
			date:  "2021-05-05 21:15:12",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsFebruary()

		eq(check, td.check, "failed IsFebruary, index "+td.index)
	}
}

func Test_IsMarch(t *testing.T) {
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
			date:  "2023-03-01 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-3",
			date:  "2021-05-05 21:15:12",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsMarch()

		eq(check, td.check, "failed IsMarch, index "+td.index)
	}
}

func Test_IsApril(t *testing.T) {
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
			date:  "2023-04-01 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-3",
			date:  "2021-05-05 21:15:12",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsApril()

		eq(check, td.check, "failed IsApril, index "+td.index)
	}
}

func Test_IsMay(t *testing.T) {
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
			date:  "2023-05-01 12:00:00",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsMay()

		eq(check, td.check, "failed IsMay, index "+td.index)
	}
}

func Test_IsJune(t *testing.T) {
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
			date:  "2023-06-01 12:00:00",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsJune()

		eq(check, td.check, "failed IsJune, index "+td.index)
	}
}

func Test_IsJuly(t *testing.T) {
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
			date:  "2023-07-01 12:00:00",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsJuly()

		eq(check, td.check, "failed IsJuly, index "+td.index)
	}
}

func Test_IsAugust(t *testing.T) {
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
			date:  "2023-08-01 12:00:00",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsAugust()

		eq(check, td.check, "failed IsAugust, index "+td.index)
	}
}

func Test_IsSeptember(t *testing.T) {
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
			date:  "2023-09-01 12:00:00",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsSeptember()

		eq(check, td.check, "failed IsSeptember, index "+td.index)
	}
}

func Test_IsOctober(t *testing.T) {
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
			date:  "2023-10-01 12:00:00",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsOctober()

		eq(check, td.check, "failed IsOctober, index "+td.index)
	}
}

func Test_IsNovember(t *testing.T) {
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
			date:  "2023-11-01 12:00:00",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsNovember()

		eq(check, td.check, "failed IsNovember, index "+td.index)
	}
}

func Test_IsDecember(t *testing.T) {
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
			date:  "2023-12-01 12:00:00",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsDecember()

		eq(check, td.check, "failed IsDecember, index "+td.index)
	}
}
