package datebin

import (
	"testing"
	"time"
)

func Test_IsZero(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  string
		check bool
	}{
		{
			index: "index-1",
			date:  "",
			check: true,
		},
		{
			index: "index-2",
			date:  "2024-06-05 21:15:12",
			check: false,
		},
	}

	for _, td := range tests {
		check := Parse(td.date).IsZero()

		eq(check, td.check, "failed IsZero, index "+td.index)
	}
}

func Test_IsInvalid(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  string
		check bool
	}{
		{
			index: "index-1",
			date:  "",
			check: true,
		},
		{
			index: "index-2",
			date:  "2024-06-05 21:15:12",
			check: false,
		},
		{
			index: "index-3",
			date:  "2024-6-05 1:15:12",
			check: true,
		},
	}

	for _, td := range tests {
		check := Parse(td.date).IsInvalid()

		eq(check, td.check, "failed IsInvalid, index "+td.index)
	}
}

func Test_IsDST(t *testing.T) {
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
			tz:    "Australia/Sydney",
			check: false,
		},
		{
			index: "index-2",
			date:  "2009-03-01 12:00:00",
			tz:    "Australia/Sydney",
			check: true,
		},
		{
			index: "index-3",
			date:  "2024-06-05 21:15:12",
			tz:    "Australia/Brisbane",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsDST()

		eq(check, td.check, "failed IsDST, index "+td.index)
	}
}

func Test_IsUTC(t *testing.T) {
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
			tz:    "UTC",
			check: true,
		},
		{
			index: "index-3",
			date:  "2024-06-05 21:15:12",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsUTC()

		eq(check, td.check, "failed IsUTC, index "+td.index)
	}
}

func Test_IsLocal(t *testing.T) {
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
			date:  "2024-06-05 21:15:12",
			tz:    "Eire",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsLocal()

		eq(check, td.check, "failed IsLocal, index "+td.index)
	}
}

func Test_IsAM(t *testing.T) {
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
			date:  "2024-03-01 10:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-3",
			date:  "2024-06-05 21:15:12",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsAM()

		eq(check, td.check, "failed IsAM, index "+td.index)
	}
}

func Test_IsPM(t *testing.T) {
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
			date:  "2024-03-01 10:00:00",
			tz:    "Local",
			check: false,
		},
		{
			index: "index-3",
			date:  "2024-06-05 21:15:12",
			tz:    "CET",
			check: true,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsPM()

		eq(check, td.check, "failed IsPM, index "+td.index)
	}
}

func Test_IsNow(t *testing.T) {
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
			check: false,
		},
		{
			index: "index-3",
			date:  "2024-06-05 21:15:12",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsNow()

		eq(check, td.check, "failed IsNow, index "+td.index)
	}
}

func Test_IsFuture(t *testing.T) {
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
			date:  "2055-03-01 12:00:00",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsFuture()

		eq(check, td.check, "failed IsFuture, index "+td.index)
	}
}

func Test_IsPast(t *testing.T) {
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
			date:  "2066-03-01 12:00:00",
			tz:    "Local",
			check: false,
		},
		{
			index: "index-3",
			date:  "2021-06-05 21:15:12",
			tz:    "CET",
			check: true,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsPast()

		eq(check, td.check, "failed IsPast, index "+td.index)
	}
}

func Test_IsLeapYear(t *testing.T) {
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsLeapYear()

		eq(check, td.check, "failed IsLeapYear, index "+td.index)
	}
}

func Test_IsLongYear(t *testing.T) {
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
			date:  "2020-03-01 12:00:00",
			tz:    "UTC",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsLongYear()

		eq(check, td.check, "failed IsLongYear, index "+td.index)
	}
}

func Test_IsToday(t *testing.T) {
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
			date:  time.Now().UTC().Format(DatetimeFormat),
			tz:    "UTC",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsToday()

		eq(check, td.check, "failed IsToday, index "+td.index)
	}
}

func Test_IsYesterday(t *testing.T) {
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
			date:  time.Now().UTC().AddDate(0, 0, -1).Format(DatetimeFormat),
			tz:    "UTC",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsYesterday()

		eq(check, td.check, "failed IsYesterday, index "+td.index)
	}
}

func Test_IsTomorrow(t *testing.T) {
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
			date:  time.Now().UTC().AddDate(0, 0, 1).Format(DatetimeFormat),
			tz:    "UTC",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsTomorrow()

		eq(check, td.check, "failed IsTomorrow, index "+td.index)
	}
}

func Test_IsCurrentYear(t *testing.T) {
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
			date:  time.Now().UTC().AddDate(0, 0, -1).Format(DatetimeFormat),
			tz:    "UTC",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsCurrentYear()

		eq(check, td.check, "failed IsCurrentYear, index "+td.index)
	}
}

func Test_IsCurrentMonth(t *testing.T) {
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
			date:  time.Now().UTC().AddDate(0, 0, -1).Format(DatetimeFormat),
			tz:    "UTC",
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
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsCurrentMonth()

		eq(check, td.check, "failed IsCurrentMonth, index "+td.index)
	}
}

func Test_IsLatelyWeek(t *testing.T) {
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
			date:  time.Now().UTC().AddDate(0, 0, -1).Format(DatetimeFormat),
			tz:    "UTC",
			check: true,
		},
		{
			index: "index-3",
			date:  "2021-06-05 21:15:12",
			tz:    "CET",
			check: false,
		},
		{
			index: "index-4",
			date:  time.Now().UTC().AddDate(0, 0, -12).Format(DatetimeFormat),
			tz:    "UTC",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsLatelyWeek()

		eq(check, td.check, "failed IsLatelyWeek, index "+td.index)
	}
}

func Test_IsLatelyMonth(t *testing.T) {
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
			date:  time.Now().UTC().AddDate(0, -1, -2).Format(DatetimeFormat),
			tz:    "UTC",
			check: true,
		},
		{
			index: "index-3",
			date:  "2021-03-05 21:15:12",
			tz:    "CET",
			check: false,
		},
		{
			index: "index-4",
			date:  time.Now().UTC().AddDate(0, 3, 0).Format(DatetimeFormat),
			tz:    "UTC",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsLatelyMonth()

		eq(check, td.check, "failed IsLatelyMonth, index "+td.index)
	}
}

func Test_IsLastOfMonth(t *testing.T) {
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
			date:  "2024-03-31 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-3",
			date:  "2024-06-05 21:15:12",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsLastOfMonth()

		eq(check, td.check, "failed IsLastOfMonth, index "+td.index)
	}
}

func Test_IsStartOfDay(t *testing.T) {
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
			date:  "2024-03-31 00:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-3",
			date:  "2024-06-05 21:15:12",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsStartOfDay()

		eq(check, td.check, "failed IsStartOfDay, index "+td.index)
	}
}

func Test_IsStartOfDayWithMicrosecond(t *testing.T) {
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
			date:  "20240331000000.000000",
			tz:    "UTC",
			check: true,
		},
		{
			index: "index-3",
			date:  "20240605211512.999999",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, ShortDatetimeMicroFormat, td.tz).IsStartOfDayWithMicrosecond()

		eq(check, td.check, "failed IsStartOfDayWithMicrosecond, index "+td.index)
	}
}

func Test_IsEndOfDay(t *testing.T) {
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
			date:  "2024-03-31 23:59:59",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-3",
			date:  "2024-06-05 21:15:12",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsEndOfDay()

		eq(check, td.check, "failed IsEndOfDay, index "+td.index)
	}
}

func Test_IsEndOfDayWithMicrosecond(t *testing.T) {
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
			date:  "20240331235959.999999",
			tz:    "UTC",
			check: true,
		},
		{
			index: "index-3",
			date:  "20240605211512.999999",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, ShortDatetimeMicroFormat, td.tz).IsEndOfDayWithMicrosecond()

		eq(check, td.check, "failed IsEndOfDayWithMicrosecond, index "+td.index)
	}
}

func Test_IsMidnight(t *testing.T) {
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
			date:  "2024-03-31 00:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-3",
			date:  "2024-06-05 21:15:12",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsMidnight()

		eq(check, td.check, "failed IsMidnight, index "+td.index)
	}
}

func Test_IsMidday(t *testing.T) {
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
			date:  "2024-03-31 12:00:00",
			tz:    "Local",
			check: true,
		},
		{
			index: "index-3",
			date:  "2024-06-05 21:15:12",
			tz:    "CET",
			check: false,
		},
	}

	for _, td := range tests {
		check := ParseWithLayout(td.date, DatetimeFormat, td.tz).IsMidday()

		eq(check, td.check, "failed IsMidday, index "+td.index)
	}
}
