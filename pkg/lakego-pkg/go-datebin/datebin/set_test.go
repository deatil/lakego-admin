package datebin

import (
    "time"
    "testing"
)

func Test_SetWeekStartsAt(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        day string
        check time.Weekday
    } {
        {
            index: "index-Monday",
            day: "Monday",
            check: time.Monday,
        },
        {
            index: "index-Tuesday",
            day: "Tuesday",
            check: time.Tuesday,
        },
        {
            index: "index-Wednesday",
            day: "Wednesday",
            check: time.Wednesday,
        },
        {
            index: "index-Thursday",
            day: "Thursday",
            check: time.Thursday,
        },
        {
            index: "index-Friday",
            day: "Friday",
            check: time.Friday,
        },
        {
            index: "index-Saturday",
            day: "Saturday",
            check: time.Saturday,
        },
        {
            index: "index-Sunday",
            day: "Sunday",
            check: time.Sunday,
        },
    }

    for _, td := range tests {
        check := NewDatebin().SetWeekStartsAt(td.day).GetWeekStartAt()

        eq(check, td.check, "failed SetWeekStartsAt, index " + td.index)
    }
}

func Test_SetDatetimeWithNanosecond(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        fn func(Datebin) Datebin
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12.999999999",
            fn: func(d Datebin) Datebin {
                return d.SetDatetimeWithNanosecond(2022, 06, 01, 12, 35, 11, 15)
            },
            check: "2022-06-01 12:35:11.000000015",
        },
        {
            index: "index-2",
            date: "2024-06-06 21:15:12.999999999",
            fn: func(d Datebin) Datebin {
                return d.SetDatetimeWithNanosecond(2021, 07, 01, 12, 35, 11, 15)
            },
            check: "2021-07-01 12:35:11.000000015",
        },
    }

    for _, td := range tests {
        tt := ParseWithLayout(td.date, DatetimeNanoFormat, UTC)
        check := td.fn(tt).ToLayoutString(DatetimeNanoFormat, UTC)

        eq(check, td.check, "failed SetDatetimeWithNanosecond, index " + td.index)
    }
}

func Test_SetDatetimeWithMicrosecond(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        fn func(Datebin) Datebin
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12.999999",
            fn: func(d Datebin) Datebin {
                return d.SetDatetimeWithMicrosecond(2022, 06, 01, 12, 35, 11, 15)
            },
            check: "2022-06-01 12:35:11.000015",
        },
        {
            index: "index-2",
            date: "2023-06-06 21:15:12.999999",
            fn: func(d Datebin) Datebin {
                return d.SetDatetimeWithMicrosecond(2020, 07, 01, 12, 35, 11, 15)
            },
            check: "2020-07-01 12:35:11.000015",
        },
    }

    for _, td := range tests {
        tt := ParseWithLayout(td.date, DatetimeMicroFormat, UTC)
        check := td.fn(tt).ToLayoutString(DatetimeMicroFormat, UTC)

        eq(check, td.check, "failed SetDatetimeWithMicrosecond, index " + td.index)
    }
}

func Test_SetDatetimeWithMillisecond(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        fn func(Datebin) Datebin
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12.999",
            fn: func(d Datebin) Datebin {
                return d.SetDatetimeWithMillisecond(2022, 06, 01, 12, 35, 11, 215)
            },
            check: "2022-06-01 12:35:11.215",
        },
        {
            index: "index-2",
            date: "2023-06-06 21:15:12.999",
            fn: func(d Datebin) Datebin {
                return d.SetDatetimeWithMillisecond(2020, 07, 01, 12, 35, 11, 15)
            },
            check: "2020-07-01 12:35:11.015",
        },
    }

    for _, td := range tests {
        tt := ParseWithLayout(td.date, DatetimeMilliFormat, UTC)
        check := td.fn(tt).ToLayoutString(DatetimeMilliFormat, UTC)

        eq(check, td.check, "failed SetDatetimeWithMillisecond, index " + td.index)
    }
}

func Test_SetDatetime(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        fn func(Datebin) Datebin
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            fn: func(d Datebin) Datebin {
                return d.SetDatetime(2022, 06, 01, 12, 35, 11)
            },
            check: "2022-06-01 12:35:11",
        },
        {
            index: "index-2",
            date: "2023-06-06 21:15:12",
            fn: func(d Datebin) Datebin {
                return d.SetDatetime(2020, 07, 01, 12, 35, 11)
            },
            check: "2020-07-01 12:35:11",
        },
    }

    for _, td := range tests {
        tt := ParseWithLayout(td.date, DatetimeFormat, UTC)
        check := td.fn(tt).ToLayoutString(DatetimeFormat, UTC)

        eq(check, td.check, "failed SetDatetime, index " + td.index)
    }
}

func Test_SetDate(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        fn func(Datebin) Datebin
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            fn: func(d Datebin) Datebin {
                return d.SetDate(2022, 02, 01)
            },
            check: "2022-02-01 21:15:12",
        },
        {
            index: "index-2",
            date: "2023-06-06 21:15:12",
            fn: func(d Datebin) Datebin {
                return d.SetDate(2020, 07, 01)
            },
            check: "2020-07-01 21:15:12",
        },
    }

    for _, td := range tests {
        tt := ParseWithLayout(td.date, DatetimeFormat, UTC)
        check := td.fn(tt).ToLayoutString(DatetimeFormat, UTC)

        eq(check, td.check, "failed SetDate, index " + td.index)
    }
}

func Test_SetTime(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        fn func(Datebin) Datebin
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            fn: func(d Datebin) Datebin {
                return d.SetTime(12, 35, 11)
            },
            check: "2024-06-06 12:35:11",
        },
        {
            index: "index-2",
            date: "2023-06-06 21:15:12",
            fn: func(d Datebin) Datebin {
                return d.SetTime(12, 35, 11)
            },
            check: "2023-06-06 12:35:11",
        },
    }

    for _, td := range tests {
        tt := ParseWithLayout(td.date, DatetimeFormat, UTC)
        check := td.fn(tt).ToLayoutString(DatetimeFormat, UTC)

        eq(check, td.check, "failed SetTime, index " + td.index)
    }
}

func Test_SetYear(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        fn func(Datebin) Datebin
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            fn: func(d Datebin) Datebin {
                return d.SetYear(2022)
            },
            check: "2022-06-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2023-06-06 21:15:12",
            fn: func(d Datebin) Datebin {
                return d.SetYear(2020)
            },
            check: "2020-06-06 21:15:12",
        },
    }

    for _, td := range tests {
        tt := ParseWithLayout(td.date, DatetimeFormat, UTC)
        check := td.fn(tt).ToLayoutString(DatetimeFormat, UTC)

        eq(check, td.check, "failed SetYear, index " + td.index)
    }
}

func Test_SetMonth(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        fn func(Datebin) Datebin
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            fn: func(d Datebin) Datebin {
                return d.SetMonth(8)
            },
            check: "2024-08-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2023-06-06 21:15:12",
            fn: func(d Datebin) Datebin {
                return d.SetMonth(1)
            },
            check: "2023-01-06 21:15:12",
        },
    }

    for _, td := range tests {
        tt := ParseWithLayout(td.date, DatetimeFormat, UTC)
        check := td.fn(tt).ToLayoutString(DatetimeFormat, UTC)

        eq(check, td.check, "failed SetMonth, index " + td.index)
    }
}

func Test_SetDay(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        fn func(Datebin) Datebin
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            fn: func(d Datebin) Datebin {
                return d.SetDay(8)
            },
            check: "2024-06-08 21:15:12",
        },
        {
            index: "index-2",
            date: "2023-06-06 21:15:12",
            fn: func(d Datebin) Datebin {
                return d.SetDay(1)
            },
            check: "2023-06-01 21:15:12",
        },
    }

    for _, td := range tests {
        tt := ParseWithLayout(td.date, DatetimeFormat, UTC)
        check := td.fn(tt).ToLayoutString(DatetimeFormat, UTC)

        eq(check, td.check, "failed SetDay, index " + td.index)
    }
}

func Test_SetHour(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        fn func(Datebin) Datebin
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            fn: func(d Datebin) Datebin {
                return d.SetHour(11)
            },
            check: "2024-06-06 11:15:12",
        },
        {
            index: "index-2",
            date: "2023-06-06 21:15:12",
            fn: func(d Datebin) Datebin {
                return d.SetHour(5)
            },
            check: "2023-06-06 05:15:12",
        },
    }

    for _, td := range tests {
        tt := ParseWithLayout(td.date, DatetimeFormat, UTC)
        check := td.fn(tt).ToLayoutString(DatetimeFormat, UTC)

        eq(check, td.check, "failed SetHour, index " + td.index)
    }
}

func Test_SetMinute(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        fn func(Datebin) Datebin
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            fn: func(d Datebin) Datebin {
                return d.SetMinute(11)
            },
            check: "2024-06-06 21:11:12",
        },
        {
            index: "index-2",
            date: "2023-06-06 21:15:12",
            fn: func(d Datebin) Datebin {
                return d.SetMinute(5)
            },
            check: "2023-06-06 21:05:12",
        },
    }

    for _, td := range tests {
        tt := ParseWithLayout(td.date, DatetimeFormat, UTC)
        check := td.fn(tt).ToLayoutString(DatetimeFormat, UTC)

        eq(check, td.check, "failed SetMinute, index " + td.index)
    }
}

func Test_SetSecond(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        fn func(Datebin) Datebin
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            fn: func(d Datebin) Datebin {
                return d.SetSecond(31)
            },
            check: "2024-06-06 21:15:31",
        },
        {
            index: "index-2",
            date: "2023-06-06 21:15:12",
            fn: func(d Datebin) Datebin {
                return d.SetSecond(5)
            },
            check: "2023-06-06 21:15:05",
        },
    }

    for _, td := range tests {
        tt := ParseWithLayout(td.date, DatetimeFormat, UTC)
        check := td.fn(tt).ToLayoutString(DatetimeFormat, UTC)

        eq(check, td.check, "failed SetSecond, index " + td.index)
    }
}

func Test_SetMillisecond(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        fn func(Datebin) Datebin
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12.999",
            fn: func(d Datebin) Datebin {
                return d.SetMillisecond(31)
            },
            check: "2024-06-06 21:15:12.031",
        },
        {
            index: "index-2",
            date: "2023-06-06 21:15:12.999",
            fn: func(d Datebin) Datebin {
                return d.SetMillisecond(5)
            },
            check: "2023-06-06 21:15:12.005",
        },
    }

    for _, td := range tests {
        tt := ParseWithLayout(td.date, DatetimeMilliFormat, UTC)
        check := td.fn(tt).ToLayoutString(DatetimeMilliFormat, UTC)

        eq(check, td.check, "failed SetMillisecond, index " + td.index)
    }
}

func Test_SetMicrosecond(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        fn func(Datebin) Datebin
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12.999999",
            fn: func(d Datebin) Datebin {
                return d.SetMicrosecond(31)
            },
            check: "2024-06-06 21:15:12.000031",
        },
        {
            index: "index-2",
            date: "2023-06-06 21:15:12.999999",
            fn: func(d Datebin) Datebin {
                return d.SetMicrosecond(5)
            },
            check: "2023-06-06 21:15:12.000005",
        },
    }

    for _, td := range tests {
        tt := ParseWithLayout(td.date, DatetimeMicroFormat, UTC)
        check := td.fn(tt).ToLayoutString(DatetimeMicroFormat, UTC)

        eq(check, td.check, "failed SetMicrosecond, index " + td.index)
    }
}

func Test_SetNanosecond(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        fn func(Datebin) Datebin
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12.999999999",
            fn: func(d Datebin) Datebin {
                return d.SetNanosecond(31)
            },
            check: "2024-06-06 21:15:12.000000031",
        },
        {
            index: "index-2",
            date: "2023-06-06 21:15:12.999999999",
            fn: func(d Datebin) Datebin {
                return d.SetNanosecond(5)
            },
            check: "2023-06-06 21:15:12.000000005",
        },
    }

    for _, td := range tests {
        tt := ParseWithLayout(td.date, DatetimeNanoFormat, UTC)
        check := td.fn(tt).ToLayoutString(DatetimeNanoFormat, UTC)

        eq(check, td.check, "failed SetNanosecond, index " + td.index)
    }
}

