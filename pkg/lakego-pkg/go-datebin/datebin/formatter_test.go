package datebin

import (
	"testing"
)

func Test_Formatter_With(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  int64
		check int64
	}{
		{
			index: "index-1",
			date:  12,
			check: 12,
		},
		{
			index: "index-2",
			date:  03,
			check: 03,
		},
	}

	for _, td := range tests {
		parseDate := NewFormatter().WithTime(td.date).time

		eq(parseDate, td.check, "failed Formatter_With, index "+td.index)
	}
}

func Test_Formatter_Get(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  int64
		check int64
	}{
		{
			index: "index-1",
			date:  12,
			check: 12,
		},
		{
			index: "index-2",
			date:  03,
			check: 03,
		},
	}

	for _, td := range tests {
		tt := Formatter{
			time: td.date,
		}
		parseDate := tt.GetTime()

		eq(parseDate, td.check, "failed Formatter_Get, index "+td.index)
	}
}

func Test_Formatter_From(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  int64
		fn    func(Formatter, int64) Formatter
		check int64
	}{
		{
			index: "index-1",
			date:  2,
			fn: func(ff Formatter, d int64) Formatter {
				return ff.FromWeek(d)
			},
			check: 1209600000000000,
		},
		{
			index: "index-2",
			date:  5,
			fn: func(ff Formatter, d int64) Formatter {
				return ff.FromDay(d)
			},
			check: 432000000000000,
		},
		{
			index: "index-3",
			date:  3,
			fn: func(ff Formatter, d int64) Formatter {
				return ff.FromHour(d)
			},
			check: 10800000000000,
		},
		{
			index: "index-4",
			date:  3,
			fn: func(ff Formatter, d int64) Formatter {
				return ff.FromMinute(d)
			},
			check: 180000000000,
		},
		{
			index: "index-5",
			date:  3,
			fn: func(ff Formatter, d int64) Formatter {
				return ff.FromSecond(d)
			},
			check: 3000000000,
		},
		{
			index: "index-6",
			date:  3,
			fn: func(ff Formatter, d int64) Formatter {
				return ff.FromMillisecond(d)
			},
			check: 3000000,
		},
		{
			index: "index-7",
			date:  3,
			fn: func(ff Formatter, d int64) Formatter {
				return ff.FromMicrosecond(d)
			},
			check: 3000,
		},
		{
			index: "index-8",
			date:  3,
			fn: func(ff Formatter, d int64) Formatter {
				return ff.FromNanosecond(d)
			},
			check: 3,
		},
	}

	for _, td := range tests {
		parseDate := td.fn(NewFormatter(), td.date).GetTime()

		eq(parseDate, td.check, "failed Formatter_Get, index "+td.index)
	}
}
