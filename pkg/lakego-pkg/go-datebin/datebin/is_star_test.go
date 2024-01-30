package datebin

import (
	"testing"
)

func Test_IsCapricornStar(t *testing.T) {
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
			date:  "2023-12-23 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-2-1",
			date:  "2023-01-15 12:00:00",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsCapricornStar()

		eq(check, td.check, "failed IsCapricornStar, index "+td.index)
	}
}

func Test_IsAquariusStar(t *testing.T) {
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
			date:  "2023-01-23 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-2-1",
			date:  "2023-02-15 12:00:00",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsAquariusStar()

		eq(check, td.check, "failed IsAquariusStar, index "+td.index)
	}
}

func Test_IsPiscesStar(t *testing.T) {
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
			date:  "2023-02-23 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-2-1",
			date:  "2023-03-15 12:00:00",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsPiscesStar()

		eq(check, td.check, "failed IsPiscesStar, index "+td.index)
	}
}

func Test_IsAriesStar(t *testing.T) {
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
			date:  "2023-03-23 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-2-1",
			date:  "2023-04-15 12:00:00",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsAriesStar()

		eq(check, td.check, "failed IsAriesStar, index "+td.index)
	}
}

func Test_IsTaurusStar(t *testing.T) {
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
			date:  "2023-05-19 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-2-1",
			date:  "2023-05-15 12:00:00",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsTaurusStar()

		eq(check, td.check, "failed IsTaurusStar, index "+td.index)
	}
}

func Test_IsGeminiStar(t *testing.T) {
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
			date:  "2023-06-19 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-2-1",
			date:  "2023-06-15 12:00:00",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsGeminiStar()

		eq(check, td.check, "failed IsGeminiStar, index "+td.index)
	}
}

func Test_IsCancerStar(t *testing.T) {
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
			date:  "2023-07-19 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-2-1",
			date:  "2023-07-15 12:00:00",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsCancerStar()

		eq(check, td.check, "failed IsCancerStar, index "+td.index)
	}
}

func Test_IsLeoStar(t *testing.T) {
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
			date:  "2023-08-19 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-2-1",
			date:  "2023-08-15 12:00:00",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsLeoStar()

		eq(check, td.check, "failed IsLeoStar, index "+td.index)
	}
}

func Test_IsVirgoStar(t *testing.T) {
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
			date:  "2023-09-19 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-2-1",
			date:  "2023-09-15 12:00:00",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsVirgoStar()

		eq(check, td.check, "failed IsVirgoStar, index "+td.index)
	}
}

func Test_IsLibraStar(t *testing.T) {
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
			date:  "2023-10-19 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-2-1",
			date:  "2023-10-15 12:00:00",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsLibraStar()

		eq(check, td.check, "failed IsLibraStar, index "+td.index)
	}
}

func Test_IsScorpioStar(t *testing.T) {
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
			date:  "2023-11-19 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-2-1",
			date:  "2023-11-15 12:00:00",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsScorpioStar()

		eq(check, td.check, "failed IsScorpioStar, index "+td.index)
	}
}

func Test_IsSagittariusStar(t *testing.T) {
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
			date:  "2023-12-19 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-2-1",
			date:  "2023-12-15 12:00:00",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsSagittariusStar()

		eq(check, td.check, "failed IsSagittariusStar, index "+td.index)
	}
}
