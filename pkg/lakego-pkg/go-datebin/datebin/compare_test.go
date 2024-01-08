package datebin

import (
	"testing"
)

func Test_Gt(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date1 string
		date2 string
		check bool
	}{
		{
			index: "index-1",
			date1: "2024-06-05 21:15:12",
			date2: "2024-06-03 21:15:12",
			check: true,
		},
		{
			index: "index-2",
			date1: "2024-06-05 21:15:12",
			date2: "2024-06-06 21:15:12",
			check: false,
		},
	}

	for _, td := range tests {
		check := Parse(td.date1).Gt(Parse(td.date2))

		eq(check, td.check, "failed Gt, index "+td.index)
	}
}

func Test_Lt(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date1 string
		date2 string
		check bool
	}{
		{
			index: "index-1",
			date1: "2024-06-05 21:15:12",
			date2: "2024-06-03 21:15:12",
			check: false,
		},
		{
			index: "index-2",
			date1: "2024-06-05 21:15:12",
			date2: "2024-06-06 21:15:12",
			check: true,
		},
	}

	for _, td := range tests {
		check := Parse(td.date1).Lt(Parse(td.date2))

		eq(check, td.check, "failed Lt, index "+td.index)
	}
}

func Test_Eq(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date1 string
		date2 string
		check bool
	}{
		{
			index: "index-1",
			date1: "2024-06-05 21:15:12",
			date2: "2024-06-05 21:15:12",
			check: true,
		},
		{
			index: "index-2",
			date1: "2024-06-05 21:15:12",
			date2: "2024-06-06 21:15:12",
			check: false,
		},
	}

	for _, td := range tests {
		check := Parse(td.date1).Eq(Parse(td.date2))

		eq(check, td.check, "failed Eq, index "+td.index)
	}
}

func Test_Ne(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date1 string
		date2 string
		check bool
	}{
		{
			index: "index-1",
			date1: "2024-06-05 21:15:12",
			date2: "2024-06-05 21:15:12",
			check: false,
		},
		{
			index: "index-2",
			date1: "2024-06-05 21:15:12",
			date2: "2024-06-06 21:15:12",
			check: true,
		},
	}

	for _, td := range tests {
		check := Parse(td.date1).Ne(Parse(td.date2))

		eq(check, td.check, "failed Ne, index "+td.index)
	}
}

func Test_Gte(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date1 string
		date2 string
		check bool
	}{
		{
			index: "index-1",
			date1: "2024-06-06 21:15:12",
			date2: "2024-06-05 21:15:12",
			check: true,
		},
		{
			index: "index-2",
			date1: "2024-06-05 21:15:12",
			date2: "2024-06-06 21:15:12",
			check: false,
		},
		{
			index: "index-3",
			date1: "2024-06-06 21:15:12",
			date2: "2024-06-06 21:15:12",
			check: true,
		},
	}

	for _, td := range tests {
		check := Parse(td.date1).Gte(Parse(td.date2))

		eq(check, td.check, "failed Gte, index "+td.index)
	}
}

func Test_Lte(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date1 string
		date2 string
		check bool
	}{
		{
			index: "index-1",
			date1: "2024-06-06 21:15:12",
			date2: "2024-06-05 21:15:12",
			check: false,
		},
		{
			index: "index-2",
			date1: "2024-06-05 21:15:12",
			date2: "2024-06-06 21:15:12",
			check: true,
		},
		{
			index: "index-3",
			date1: "2024-06-06 21:15:12",
			date2: "2024-06-06 21:15:12",
			check: true,
		},
	}

	for _, td := range tests {
		check := Parse(td.date1).Lte(Parse(td.date2))

		eq(check, td.check, "failed Lte, index "+td.index)
	}
}

func Test_Between(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  string
		start string
		end   string
		check bool
	}{
		{
			index: "index-1",
			date:  "2024-06-06 21:15:12",
			start: "2024-06-05 21:15:12",
			end:   "2024-07-05 21:15:12",
			check: true,
		},
		{
			index: "index-2",
			date:  "2024-08-06 21:15:12",
			start: "2024-06-05 21:15:12",
			end:   "2024-07-05 21:15:12",
			check: false,
		},
	}

	for _, td := range tests {
		check := Parse(td.date).Between(Parse(td.start), Parse(td.end))

		eq(check, td.check, "failed Between, index "+td.index)
	}
}

func Test_BetweenIncluded(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  string
		start string
		end   string
		check bool
	}{
		{
			index: "index-1",
			date:  "2024-06-06 21:15:12",
			start: "2024-06-05 21:15:12",
			end:   "2024-07-05 21:15:12",
			check: true,
		},
		{
			index: "index-2",
			date:  "2024-08-06 21:15:12",
			start: "2024-06-05 21:15:12",
			end:   "2024-07-05 21:15:12",
			check: false,
		},
		{
			index: "index-3",
			date:  "2024-07-05 21:15:12",
			start: "2024-06-05 21:15:12",
			end:   "2024-07-05 21:15:12",
			check: true,
		},
		{
			index: "index-4",
			date:  "2024-06-06 21:15:12",
			start: "2024-06-06 21:15:12",
			end:   "2024-07-05 21:15:12",
			check: true,
		},
	}

	for _, td := range tests {
		check := Parse(td.date).BetweenIncluded(Parse(td.start), Parse(td.end))

		eq(check, td.check, "failed BetweenIncluded, index "+td.index)
	}
}

func Test_BetweenIncludStart(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  string
		start string
		end   string
		check bool
	}{
		{
			index: "index-1",
			date:  "2024-06-06 21:15:12",
			start: "2024-06-05 21:15:12",
			end:   "2024-07-05 21:15:12",
			check: true,
		},
		{
			index: "index-2",
			date:  "2024-08-06 21:15:12",
			start: "2024-06-05 21:15:12",
			end:   "2024-07-05 21:15:12",
			check: false,
		},
		{
			index: "index-3",
			date:  "2024-07-05 21:15:12",
			start: "2024-06-05 21:15:12",
			end:   "2024-07-05 21:15:12",
			check: false,
		},
		{
			index: "index-4",
			date:  "2024-06-06 21:15:12",
			start: "2024-06-06 21:15:12",
			end:   "2024-07-05 21:15:12",
			check: true,
		},
	}

	for _, td := range tests {
		check := Parse(td.date).BetweenIncludStart(Parse(td.start), Parse(td.end))

		eq(check, td.check, "failed BetweenIncludStart, index "+td.index)
	}
}

func Test_BetweenIncludEnd(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  string
		start string
		end   string
		check bool
	}{
		{
			index: "index-1",
			date:  "2024-06-06 21:15:12",
			start: "2024-06-05 21:15:12",
			end:   "2024-07-05 21:15:12",
			check: true,
		},
		{
			index: "index-2",
			date:  "2024-08-06 21:15:12",
			start: "2024-06-05 21:15:12",
			end:   "2024-07-05 21:15:12",
			check: false,
		},
		{
			index: "index-3",
			date:  "2024-07-05 21:15:12",
			start: "2024-06-05 21:15:12",
			end:   "2024-07-05 21:15:12",
			check: true,
		},
		{
			index: "index-4",
			date:  "2024-06-06 21:15:12",
			start: "2024-06-06 21:15:12",
			end:   "2024-07-05 21:15:12",
			check: false,
		},
	}

	for _, td := range tests {
		check := Parse(td.date).BetweenIncludEnd(Parse(td.start), Parse(td.end))

		eq(check, td.check, "failed BetweenIncludEnd, index "+td.index)
	}
}
