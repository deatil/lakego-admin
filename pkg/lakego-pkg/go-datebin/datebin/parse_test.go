package datebin

import (
	"testing"
	"time"
)

func Test_Parse(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index  string
		format string
		date   string
	}{
		{
			index:  "index-1",
			format: "2006-01-02 15:04:05",
			date:   "2024-01-03 21:15:12",
		},
		{
			index:  "index-2",
			format: "20060102150405.999",
			date:   "20240103211512.666",
		},
		{
			index:  "index-3",
			format: "2006-01-02",
			date:   "2024-01-03",
		},
		{
			index:  "index-4",
			format: "20060102",
			date:   "20240103",
		},
		{
			index:  "index-5",
			format: "20060102150405",
			date:   "20240103211512",
		},
		{
			index:  "index-6",
			format: "2006-01-02 15:04:05.999",
			date:   "2024-01-03 21:15:12.123",
		},
		{
			index:  "index-7",
			format: "2006-01-02 15:04:05.999999",
			date:   "2024-01-03 21:15:12.123123",
		},
		{
			index:  "index-8",
			format: "2006-01-02 15:04:05.999999999",
			date:   "2024-01-03 21:15:12.123123123",
		},
	}

	for _, td := range tests {
		tt, err := time.Parse(td.format, td.date)
		if err != nil {
			t.Fatal(err)
		}

		parseTt := Parse(td.date).time

		eq(parseTt, tt, "failed Parse, index "+td.index)
	}
}

func Test_Parse2(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index  string
		format string
		tz     string
		date   string
	}{
		{
			index:  "index-1",
			format: "2006-01-02 15:04:05",
			tz:     "CET",
			date:   "2024-01-03 21:15:12",
		},
		{
			index:  "index-2",
			format: "20060102150405.999",
			tz:     "EET",
			date:   "20240103211512.666",
		},
		{
			index:  "index-3",
			format: "2006-01-02",
			tz:     "UCT",
			date:   "2024-01-03",
		},
		{
			index:  "index-4",
			format: "20060102",
			tz:     "Poland",
			date:   "20240103",
		},
		{
			index:  "index-5",
			format: "20060102150405",
			tz:     "Asia/Shanghai",
			date:   "20240103211512",
		},
		{
			index:  "index-6",
			format: "2006-01-02 15:04:05.999",
			tz:     "Asia/Shanghai",
			date:   "2024-01-03 21:15:12.123",
		},
		{
			index:  "index-7",
			format: "2006-01-02 15:04:05.999999",
			tz:     "Asia/Shanghai",
			date:   "2024-01-03 21:15:12.123123",
		},
		{
			index:  "index-8",
			format: "2006-01-02 15:04:05.999999999",
			tz:     "Asia/Shanghai",
			date:   "2024-01-03 21:15:12.123123123",
		},
	}

	for _, td := range tests {
		loc, _ := time.LoadLocation(td.tz)
		tt, err := time.Parse(td.format, td.date)
		if err != nil {
			t.Fatal(err)
		}

		parseTt := Parse(td.date, td.tz).time

		eq(parseTt, tt.In(loc), "failed Parse2, index "+td.index)
	}
}

func Test_ParseWithLayout(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index  string
		format string
		date   string
	}{
		{
			index:  "index-1",
			format: "2006-01-02 15:04:05",
			date:   "2024-01-03 21:15:12",
		},
		{
			index:  "index-2",
			format: "20060102150405.999",
			date:   "20240103211512.666",
		},
		{
			index:  "index-3",
			format: "2006-01-02",
			date:   "2024-01-03",
		},
		{
			index:  "index-4",
			format: "20060102",
			date:   "20240103",
		},
		{
			index:  "index-5",
			format: "20060102150405",
			date:   "20240103211512",
		},
	}

	for _, td := range tests {
		tt, err := time.ParseInLocation(td.format, td.date, time.Local)
		if err != nil {
			t.Fatal(err)
		}

		parseTt := ParseWithLayout(td.date, td.format).time

		eq(parseTt, tt, "failed ParseWithLayout, index "+td.index)
	}
}

func Test_ParseWithFormat(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index  string
		layout string
		format string
		date   string
	}{
		{
			index:  "index-1",
			layout: "2006-01-02 15:04:05",
			format: "Y-m-d H:i:s",
			date:   "2024-01-03 21:15:12",
		},
		{
			index:  "index-2",
			layout: "2006-01-02 15:04:05.999999",
			format: "Y-m-d H:i:s.u",
			date:   "2024-01-03 21:15:12.666666",
		},
		{
			index:  "index-3",
			layout: "2006-01-02",
			format: "Y-m-d",
			date:   "2024-01-03",
		},
		{
			index:  "index-4",
			layout: "20060102",
			format: "Ymd",
			date:   "20240103",
		},
		{
			index:  "index-5",
			layout: "20060102150405",
			format: "YmdHis",
			date:   "20240103211512",
		},
	}

	for _, td := range tests {
		tt, err := time.ParseInLocation(td.layout, td.date, time.Local)
		if err != nil {
			t.Fatal(err)
		}

		parseTt := ParseWithFormat(td.date, td.format).time

		eq(parseTt, tt, "failed ParseWithFormat, index "+td.index)
	}
}

func Test_ParseDatetimeString(t *testing.T) {
	eq := assertEqualT(t)

	tests := []struct {
		index  string
		typ    string
		layout string
		format string
		date   string
	}{
		{
			index:  "index-1",
			typ:    "u",
			layout: "2006-01-02 15:04:05",
			format: "Y-m-d H:i:s",
			date:   "2024-01-03 21:15:12",
		},
		{
			index:  "index-2",
			typ:    "n",
			layout: "20060102150405",
			format: "20060102150405",
			date:   "20240103211512",
		},
	}

	for _, td := range tests {
		tt, err := time.ParseInLocation(td.layout, td.date, time.Local)
		if err != nil {
			t.Fatal(err)
		}

		parseTt := ParseDatetimeString(td.date, td.format, td.typ).time

		eq(parseTt, tt, "failed ParseDatetimeString, index "+td.index)
	}
}
