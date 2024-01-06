package datebin

import (
    "testing"
)

func Test_IsSameAs(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date1 string
        date2 string
        format string
        check bool
    } {
        {
            index: "index-1",
            date1: "2024-06-05 21:15:12",
            date2: "2024-06-03 21:15:12",
            format: "Y-m-d H:i:s",
            check: false,
        },
        {
            index: "index-2",
            date1: "2024-06-05 21:15:12",
            date2: "2024-06-05 21:15:12",
            format: "Y-m-d H:i:s",
            check: true,
        },
        {
            index: "index-3",
            date1: "2024-06-05 21:15:12",
            date2: "2024-06-05 21:15:15",
            format: "Y-m-d H:i",
            check: true,
        },
        {
            index: "index-4",
            date1: "2024-06-05 21:15:12",
            date2: "2024-06-06 21:15:15",
            format: "Y-m H:i",
            check: true,
        },
    }

    for _, td := range tests {
        check := Parse(td.date1).IsSameAs(td.format, Parse(td.date2))

        eq(check, td.check, "failed IsSameAs, index " + td.index)
    }
}

func Test_IsSameAsWithLayout(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date1 string
        date2 string
        layout string
        check bool
    } {
        {
            index: "index-1",
            date1: "2024-06-05 21:15:12",
            date2: "2024-06-03 21:15:12",
            layout: "2006-01-02 15:04:05",
            check: false,
        },
        {
            index: "index-2",
            date1: "2024-06-05 21:15:12",
            date2: "2024-06-05 21:15:12",
            layout: "2006-01-02 15:04:05",
            check: true,
        },
        {
            index: "index-3",
            date1: "2024-06-05 21:15:12",
            date2: "2024-06-05 21:15:15",
            layout: "2006-01-02 15:04",
            check: true,
        },
        {
            index: "index-4",
            date1: "2024-06-05 21:15:12",
            date2: "2024-06-06 21:15:15",
            layout: "2006-01 15:04",
            check: true,
        },
    }

    for _, td := range tests {
        check := Parse(td.date1).IsSameAsWithLayout(td.layout, Parse(td.date2))

        eq(check, td.check, "failed IsSameAsWithLayout, index " + td.index)
    }
}

func Test_IsSameUnit(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date1 string
        date2 string
        unit string
        check bool
    } {
        {
            index: "index-1",
            date1: "2024-06-05 21:15:12",
            date2: "2024-06-03 21:15:12",
            unit: "minute",
            check: false,
        },
        {
            index: "index-2",
            date1: "2024-06-05 21:15:12",
            date2: "2024-06-05 21:15:12",
            unit: "minute",
            check: true,
        },
        {
            index: "index-3",
            date1: "2024-06-05 21:15:12",
            date2: "2024-06-05 21:15:15",
            unit: "day",
            check: true,
        },
        {
            index: "index-4",
            date1: "2024-06-05 21:15:12",
            date2: "2024-06-06 21:15:15",
            unit: "week",
            check: true,
        },
    }

    for _, td := range tests {
        check := Parse(td.date1).IsSameUnit(td.unit, Parse(td.date2))

        eq(check, td.check, "failed IsSameUnit, index " + td.index)
    }
}

func Test_IsSameYear(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date1 string
        date2 string
        check bool
    } {
        {
            index: "index-1",
            date1: "2023-06-05 21:15:12",
            date2: "2024-06-03 21:15:12",
            check: false,
        },
        {
            index: "index-2",
            date1: "2024-06-05 21:15:12",
            date2: "2024-06-05 21:15:12",
            check: true,
        },
    }

    for _, td := range tests {
        check := Parse(td.date1).IsSameYear(Parse(td.date2))

        eq(check, td.check, "failed IsSameYear, index " + td.index)
    }
}

func Test_IsSameMonth(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date1 string
        date2 string
        check bool
    } {
        {
            index: "index-1",
            date1: "2023-06-05 21:15:12",
            date2: "2024-07-03 21:15:12",
            check: false,
        },
        {
            index: "index-2",
            date1: "2024-06-05 21:15:12",
            date2: "2021-06-05 21:15:12",
            check: true,
        },
    }

    for _, td := range tests {
        check := Parse(td.date1).IsSameMonth(Parse(td.date2))

        eq(check, td.check, "failed IsSameMonth, index " + td.index)
    }
}

func Test_IsSameDay(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date1 string
        date2 string
        check bool
    } {
        {
            index: "index-1",
            date1: "2023-06-05 21:15:12",
            date2: "2024-07-03 21:15:12",
            check: false,
        },
        {
            index: "index-2",
            date1: "2024-06-05 21:15:12",
            date2: "2021-06-05 21:15:12",
            check: true,
        },
    }

    for _, td := range tests {
        check := Parse(td.date1).IsSameDay(Parse(td.date2))

        eq(check, td.check, "failed IsSameDay, index " + td.index)
    }
}

func Test_IsSameHour(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date1 string
        date2 string
        check bool
    } {
        {
            index: "index-1",
            date1: "2023-06-05 21:15:12",
            date2: "2024-07-03 22:15:12",
            check: false,
        },
        {
            index: "index-2",
            date1: "2024-06-05 21:15:12",
            date2: "2021-06-07 21:12:11",
            check: true,
        },
    }

    for _, td := range tests {
        check := Parse(td.date1).IsSameHour(Parse(td.date2))

        eq(check, td.check, "failed IsSameHour, index " + td.index)
    }
}

func Test_IsSameMinute(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date1 string
        date2 string
        check bool
    } {
        {
            index: "index-1",
            date1: "2023-06-05 21:15:12",
            date2: "2024-07-03 22:11:13",
            check: false,
        },
        {
            index: "index-2",
            date1: "2024-06-05 21:15:12",
            date2: "2021-06-07 21:15:13",
            check: true,
        },
    }

    for _, td := range tests {
        check := Parse(td.date1).IsSameMinute(Parse(td.date2))

        eq(check, td.check, "failed IsSameMinute, index " + td.index)
    }
}

func Test_IsSameSecond(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date1 string
        date2 string
        check bool
    } {
        {
            index: "index-1",
            date1: "2023-06-05 21:15:12",
            date2: "2024-07-03 22:11:13",
            check: false,
        },
        {
            index: "index-2",
            date1: "2024-06-05 21:15:12",
            date2: "2021-06-07 23:16:12",
            check: true,
        },
    }

    for _, td := range tests {
        check := Parse(td.date1).IsSameSecond(Parse(td.date2))

        eq(check, td.check, "failed IsSameSecond, index " + td.index)
    }
}

func Test_IsSameYearMonth(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date1 string
        date2 string
        check bool
    } {
        {
            index: "index-1",
            date1: "2023-06-05 21:15:12",
            date2: "2024-07-03 22:11:13",
            check: false,
        },
        {
            index: "index-2",
            date1: "2024-06-05 21:15:12",
            date2: "2024-06-07 23:16:11",
            check: true,
        },
    }

    for _, td := range tests {
        check := Parse(td.date1).IsSameYearMonth(Parse(td.date2))

        eq(check, td.check, "failed IsSameYearMonth, index " + td.index)
    }
}

func Test_IsSameMonthDay(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date1 string
        date2 string
        check bool
    } {
        {
            index: "index-1",
            date1: "2023-06-05 21:15:12",
            date2: "2024-07-03 22:11:13",
            check: false,
        },
        {
            index: "index-2",
            date1: "2024-06-05 21:15:12",
            date2: "2021-06-05 23:16:11",
            check: true,
        },
    }

    for _, td := range tests {
        check := Parse(td.date1).IsSameMonthDay(Parse(td.date2))

        eq(check, td.check, "failed IsSameMonthDay, index " + td.index)
    }
}

func Test_IsSameYearMonthDay(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date1 string
        date2 string
        check bool
    } {
        {
            index: "index-1",
            date1: "2023-06-05 21:15:12",
            date2: "2024-07-03 22:11:13",
            check: false,
        },
        {
            index: "index-2",
            date1: "2024-06-05 21:15:12",
            date2: "2024-06-05 23:16:11",
            check: true,
        },
    }

    for _, td := range tests {
        check := Parse(td.date1).IsSameYearMonthDay(Parse(td.date2))

        eq(check, td.check, "failed IsSameYearMonthDay, index " + td.index)
    }
}

func Test_IsSameBirthday(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date1 string
        date2 string
        check bool
    } {
        {
            index: "index-1",
            date1: "2023-06-05 21:15:12",
            date2: "2024-07-03 22:11:13",
            check: false,
        },
        {
            index: "index-2",
            date1: "2024-06-05 21:15:12",
            date2: "2021-06-05 23:16:11",
            check: true,
        },
    }

    for _, td := range tests {
        check := Parse(td.date1).IsSameBirthday(Parse(td.date2))

        eq(check, td.check, "failed IsSameBirthday, index " + td.index)
    }
}

