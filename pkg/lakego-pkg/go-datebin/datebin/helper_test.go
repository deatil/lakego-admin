package datebin

import (
	"testing"
	"time"
)

func Test_NowTimestamp(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  func() int64
		check func() int64
	}{
		{
			index: "index-1",
			date: func() int64 {
				return NowTimestamp()
			},
			check: func() int64 {
				return time.Now().In(time.Local).Unix()
			},
		},
	}

	for _, td := range tests {
		check := td.date()

		eq(check, td.check(), "failed NowTimestamp, index "+td.index)
	}
}

func Test_NowDatetimeString(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  func() string
		check func() string
	}{
		{
			index: "index-1",
			date: func() string {
				return NowDatetimeString()
			},
			check: func() string {
				return time.Now().In(time.Local).Format(DatetimeFormat)
			},
		},
	}

	for _, td := range tests {
		check := td.date()

		eq(check, td.check(), "failed NowDatetimeString, index "+td.index)
	}
}

func Test_NowDateString(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  func() string
		check func() string
	}{
		{
			index: "index-1",
			date: func() string {
				return NowDateString()
			},
			check: func() string {
				return time.Now().In(time.Local).Format(DateFormat)
			},
		},
	}

	for _, td := range tests {
		check := td.date()

		eq(check, td.check(), "failed NowDateString, index "+td.index)
	}
}

func Test_NowTimeString(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  func() string
		check func() string
	}{
		{
			index: "index-1",
			date: func() string {
				return NowTimeString()
			},
			check: func() string {
				return time.Now().In(time.Local).Format(TimeFormat)
			},
		},
	}

	for _, td := range tests {
		check := td.date()

		eq(check, td.check(), "failed NowTimeString, index "+td.index)
	}
}

func Test_TimestampToStdTime(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  func() time.Time
		check func() time.Time
	}{
		{
			index: "index-1",
			date: func() time.Time {
				return TimestampToStdTime(int64(1624599311))
			},
			check: func() time.Time {
				t, _ := time.Parse(DatetimeFormat, "2021-06-25 05:35:11")

				return t.In(time.Local)
			},
		},
		{
			index: "index-2",
			date: func() time.Time {
				return TimestampToStdTime(int64(1664112911))
			},
			check: func() time.Time {
				t, _ := time.Parse(DatetimeFormat, "2022-09-25 13:35:11")

				return t.In(time.Local)
			},
		},
	}

	for _, td := range tests {
		check := td.date()

		eq(check, td.check(), "failed TimestampToStdTime, index "+td.index)
	}
}

func Test_StdTimeToTimestamp(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  func() int64
		check int64
	}{
		{
			index: "index-1",
			date: func() int64 {
				t, _ := time.Parse(DatetimeFormat, "2021-06-25 05:35:11")

				return StdTimeToTimestamp(t)
			},
			check: 1624599311,
		},
		{
			index: "index-2",
			date: func() int64 {
				t, _ := time.Parse(DatetimeFormat, "2022-09-25 13:35:11")

				return StdTimeToTimestamp(t)
			},
			check: 1664112911,
		},
	}

	for _, td := range tests {
		check := td.date()

		eq(check, td.check, "failed StdTimeToTimestamp, index "+td.index)
	}
}

func Test_StringToStdTime(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  func() time.Time
		check func() time.Time
	}{
		{
			index: "index-1",
			date: func() time.Time {
				return StringToStdTime("2021-06-25 05:35:11").In(time.Local)
			},
			check: func() time.Time {
				t, _ := time.Parse(DatetimeFormat, "2021-06-25 05:35:11")

				return t.In(time.Local)
			},
		},
		{
			index: "index-2",
			date: func() time.Time {
				return StringToStdTime("2022-09-25 13:35:11").In(time.Local)
			},
			check: func() time.Time {
				t, _ := time.Parse(DatetimeFormat, "2022-09-25 13:35:11")

				return t.In(time.Local)
			},
		},
	}

	for _, td := range tests {
		check := td.date()

		eq(check, td.check(), "failed StringToStdTime, index "+td.index)
	}
}

func Test_StringToTimestamp(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index string
		date  func() int64
		check func() int64
	}{
		{
			index: "index-1",
			date: func() int64 {
				return StringToTimestamp("2021-06-25 05:35:11")
			},
			check: func() int64 {
				t, _ := time.Parse(DatetimeFormat, "2021-06-25 05:35:11")

				return t.Unix()
			},
		},
		{
			index: "index-2",
			date: func() int64 {
				return StringToTimestamp("2022-09-25 13:35:11")
			},
			check: func() int64 {
				t, _ := time.Parse(DatetimeFormat, "2022-09-25 13:35:11")

				return t.Unix()
			},
		},
		{
			index: "index-3",
			date: func() int64 {
				return StringToTimestamp("2022-09-25 13:35:11", DatetimeFormat)
			},
			check: func() int64 {
				t, _ := time.ParseInLocation(DatetimeFormat, "2022-09-25 13:35:11", time.Local)

				return t.Unix()
			},
		},
	}

	for _, td := range tests {
		check := td.date()

		eq(check, td.check(), "failed StringToStdTime, index "+td.index)
	}
}
