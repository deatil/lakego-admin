package datebin

import (
	"testing"
)

func Test_Offset(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index  string
		date   string
		field  string
		offset int
		check  string
	}{
		{
			index:  "index-1",
			date:   "2024-06-06 21:15:12",
			field:  "century",
			offset: 1,
			check:  "2124-06-06 21:15:12",
		},
		{
			index:  "index-2",
			date:   "2024-06-06 21:15:12",
			field:  "year",
			offset: 1,
			check:  "2025-06-06 21:15:12",
		},
		{
			index:  "index-3",
			date:   "2024-06-06 21:15:12",
			field:  "month",
			offset: 1,
			check:  "2024-07-06 21:15:12",
		},
		{
			index:  "index-4",
			date:   "2024-06-06 21:15:12",
			field:  "hour",
			offset: 5,
			check:  "2024-06-07 02:15:12",
		},
	}

	for _, td := range tests {
		check := Parse(td.date).Offset(td.field, td.offset)

		eq(check.ToDatetimeString(UTC), td.check, "failed Offset, index "+td.index)
	}
}

func Test_OffsetYearsNoOverflow(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  string
		years int
		check string
	}{
		{
			index: "index-1",
			date:  "2024-06-06 21:15:12",
			years: 1,
			check: "2025-06-06 21:15:12",
		},
		{
			index: "index-2",
			date:  "2021-06-06 21:15:12",
			years: 2,
			check: "2023-06-06 21:15:12",
		},
	}

	for _, td := range tests {
		check := Parse(td.date).OffsetYearsNoOverflow(td.years)

		eq(check.ToDatetimeString(UTC), td.check, "failed OffsetYearsNoOverflow, index "+td.index)
	}
}

func Test_OffsetMonthsNoOverflow(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index  string
		date   string
		months int
		check  string
	}{
		{
			index:  "index-1",
			date:   "2024-06-06 21:15:12",
			months: 1,
			check:  "2024-07-06 21:15:12",
		},
		{
			index:  "index-2",
			date:   "2021-06-06 21:15:12",
			months: 2,
			check:  "2021-08-06 21:15:12",
		},
	}

	for _, td := range tests {
		check := Parse(td.date).OffsetMonthsNoOverflow(td.months)

		eq(check.ToDatetimeString(UTC), td.check, "failed OffsetMonthsNoOverflow, index "+td.index)
	}
}

func Test_AddDuration(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index    string
		date     string
		duration string
		check    string
	}{
		{
			index:    "index-1",
			date:     "2024-06-06 21:15:12",
			duration: "2h52m",
			check:    "2024-06-07 00:07:12",
		},
		{
			index:    "index-2",
			date:     "2021-06-06 21:15:12",
			duration: "32m",
			check:    "2021-06-06 21:47:12",
		},
	}

	for _, td := range tests {
		check := Parse(td.date).AddDuration(td.duration)

		eq(check.ToDatetimeString(UTC), td.check, "failed AddDuration, index "+td.index)
	}
}

func Test_SubDuration(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index    string
		date     string
		duration string
		check    string
	}{
		{
			index:    "index-1",
			date:     "2024-06-06 21:15:12",
			duration: "2h52m",
			check:    "2024-06-06 18:23:12",
		},
		{
			index:    "index-2",
			date:     "2021-06-06 21:15:12",
			duration: "32m",
			check:    "2021-06-06 20:43:12",
		},
	}

	for _, td := range tests {
		check := Parse(td.date).SubDuration(td.duration)

		eq(check.ToDatetimeString(UTC), td.check, "failed SubDuration, index "+td.index)
	}
}

func Test_AddBusinessDays(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  string
		days  int
		check string
	}{
		{
			index: "index-1",
			date:  "2023-08-01 21:15:12",
			days:  5,
			check: "2023-08-08 21:15:12",
		},
		{
			index: "index-2",
			date:  "2021-06-25 05:35:11",
			days:  16,
			check: "2021-07-19 05:35:11",
		},
	}

	for _, td := range tests {
		check := Parse(td.date, UTC).AddBusinessDays(td.days)

		eq(check.ToDatetimeString(UTC), td.check, "failed AddBusinessDays, index "+td.index)
	}
}
