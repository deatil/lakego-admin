package datebin

import (
    "testing"
)

func Test_SubCenturies(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        century uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            century: 1,
            check: "1924-06-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            century: 2,
            check: "1821-06-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubCenturies(td.century)

        eq(check.ToDatetimeString(UTC), td.check, "failed SubCenturies, index " + td.index)
    }
}

func Test_SubCenturiesNoOverflow(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        century uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            century: 1,
            check: "1924-06-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            century: 2,
            check: "1821-06-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubCenturiesNoOverflow(td.century)

        eq(check.ToDatetimeString(UTC), td.check, "failed SubCenturiesNoOverflow, index " + td.index)
    }
}

func Test_SubCentury(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "1924-06-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "1921-06-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubCentury()

        eq(check.ToDatetimeString(UTC), td.check, "failed SubCentury, index " + td.index)
    }
}

func Test_SubCenturyNoOverflow(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "1924-06-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "1921-06-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubCenturyNoOverflow()

        eq(check.ToDatetimeString(UTC), td.check, "failed SubCenturyNoOverflow, index " + td.index)
    }
}

func Test_AddCenturies(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        century uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            century: 1,
            check: "2124-06-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            century: 2,
            check: "2221-06-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddCenturies(td.century)

        eq(check.ToDatetimeString(UTC), td.check, "failed AddCenturies, index " + td.index)
    }
}

func Test_AddCenturiesNoOverflow(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        century uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            century: 1,
            check: "2124-06-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            century: 2,
            check: "2221-06-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddCenturiesNoOverflow(td.century)

        eq(check.ToDatetimeString(UTC), td.check, "failed AddCenturiesNoOverflow, index " + td.index)
    }
}

func Test_AddCentury(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2124-06-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2121-06-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddCentury()

        eq(check.ToDatetimeString(UTC), td.check, "failed AddCentury, index " + td.index)
    }
}

func Test_AddCenturyNoOverflow(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2124-06-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2121-06-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddCenturyNoOverflow()

        eq(check.ToDatetimeString(UTC), td.check, "failed AddCenturyNoOverflow, index " + td.index)
    }
}

func Test_SubDecades(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            num: 1,
            check: "2014-06-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            num: 2,
            check: "2001-06-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubDecades(td.num)

        eq(check.ToDatetimeString(UTC), td.check, "failed SubDecades, index " + td.index)
    }
}

func Test_SubDecadesNoOverflow(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            num: 1,
            check: "2014-06-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            num: 2,
            check: "2001-06-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubDecadesNoOverflow(td.num)

        eq(check.ToDatetimeString(UTC), td.check, "failed SubDecadesNoOverflow, index " + td.index)
    }
}

func Test_SubDecade(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2014-06-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2011-06-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubDecade()

        eq(check.ToDatetimeString(UTC), td.check, "failed SubDecade, index " + td.index)
    }
}

func Test_SubDecadeNoOverflow(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2014-06-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2011-06-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubDecadeNoOverflow()

        eq(check.ToDatetimeString(UTC), td.check, "failed SubDecadeNoOverflow, index " + td.index)
    }
}

func Test_AddDecades(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            num: 1,
            check: "2034-06-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            num: 2,
            check: "2041-06-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddDecades(td.num)

        eq(check.ToDatetimeString(UTC), td.check, "failed AddDecades, index " + td.index)
    }
}

func Test_AddDecadesNoOverflow(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            num: 1,
            check: "2034-06-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            num: 2,
            check: "2041-06-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddDecadesNoOverflow(td.num)

        eq(check.ToDatetimeString(UTC), td.check, "failed AddDecadesNoOverflow, index " + td.index)
    }
}

func Test_AddDecade(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2034-06-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2031-06-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddDecade()

        eq(check.ToDatetimeString(UTC), td.check, "failed AddDecade, index " + td.index)
    }
}

func Test_AddDecadeNoOverflow(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2034-06-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2031-06-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddDecadeNoOverflow()

        eq(check.ToDatetimeString(UTC), td.check, "failed AddDecadeNoOverflow, index " + td.index)
    }
}

func Test_SubYears(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            num: 1,
            check: "2023-06-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            num: 2,
            check: "2019-06-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubYears(td.num)

        eq(check.ToDatetimeString(UTC), td.check, "failed SubYears, index " + td.index)
    }
}

func Test_SubYearsNoOverflow(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            num: 1,
            check: "2023-06-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            num: 2,
            check: "2019-06-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubYearsNoOverflow(td.num)

        eq(check.ToDatetimeString(UTC), td.check, "failed SubYearsNoOverflow, index " + td.index)
    }
}

func Test_SubYear(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2023-06-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2020-06-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubYear()

        eq(check.ToDatetimeString(UTC), td.check, "failed SubYear, index " + td.index)
    }
}

func Test_SubYearNoOverflow(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2023-06-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2020-06-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubYearNoOverflow()

        eq(check.ToDatetimeString(UTC), td.check, "failed SubYearNoOverflow, index " + td.index)
    }
}

func Test_AddYears(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            num: 1,
            check: "2025-06-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            num: 2,
            check: "2023-06-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddYears(td.num)

        eq(check.ToDatetimeString(UTC), td.check, "failed AddYears, index " + td.index)
    }
}

func Test_AddYearsNoOverflow(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            num: 1,
            check: "2025-06-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            num: 2,
            check: "2023-06-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddYearsNoOverflow(td.num)

        eq(check.ToDatetimeString(UTC), td.check, "failed AddYearsNoOverflow, index " + td.index)
    }
}

func Test_AddYear(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2025-06-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2022-06-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddYear()

        eq(check.ToDatetimeString(UTC), td.check, "failed AddYear, index " + td.index)
    }
}

func Test_AddYearNoOverflow(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2025-06-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2022-06-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddYearNoOverflow()

        eq(check.ToDatetimeString(UTC), td.check, "failed AddYearNoOverflow, index " + td.index)
    }
}

func Test_SubQuarters(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            num: 1,
            check: "2024-03-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            num: 2,
            check: "2020-12-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubQuarters(td.num)

        eq(check.ToDatetimeString(UTC), td.check, "failed SubQuarters, index " + td.index)
    }
}

func Test_SubQuartersNoOverflow(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            num: 1,
            check: "2024-03-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            num: 2,
            check: "2020-12-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubQuartersNoOverflow(td.num)

        eq(check.ToDatetimeString(UTC), td.check, "failed SubQuartersNoOverflow, index " + td.index)
    }
}

func Test_SubQuarter(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2024-03-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2021-03-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubQuarter()

        eq(check.ToDatetimeString(UTC), td.check, "failed SubQuarter, index " + td.index)
    }
}

func Test_SubQuarterNoOverflow(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2024-03-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2021-03-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubQuarterNoOverflow()

        eq(check.ToDatetimeString(UTC), td.check, "failed SubQuarterNoOverflow, index " + td.index)
    }
}

func Test_AddQuarters(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            num: 1,
            check: "2024-09-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            num: 2,
            check: "2021-12-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddQuarters(td.num)

        eq(check.ToDatetimeString(UTC), td.check, "failed AddQuarters, index " + td.index)
    }
}

func Test_AddQuartersNoOverflow(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            num: 1,
            check: "2024-09-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            num: 2,
            check: "2021-12-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddQuartersNoOverflow(td.num)

        eq(check.ToDatetimeString(UTC), td.check, "failed AddQuartersNoOverflow, index " + td.index)
    }
}

func Test_AddQuarter(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2024-09-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2021-09-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddQuarter()

        eq(check.ToDatetimeString(UTC), td.check, "failed AddQuarter, index " + td.index)
    }
}

func Test_AddQuarterNoOverflow(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2024-09-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2021-09-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddQuarterNoOverflow()

        eq(check.ToDatetimeString(UTC), td.check, "failed AddQuarterNoOverflow, index " + td.index)
    }
}

func Test_SubMonths(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            num: 1,
            check: "2024-05-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            num: 2,
            check: "2021-04-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubMonths(td.num)

        eq(check.ToDatetimeString(UTC), td.check, "failed SubMonths, index " + td.index)
    }
}

func Test_SubMonthsNoOverflow(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            num: 1,
            check: "2024-05-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            num: 2,
            check: "2021-04-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubMonthsNoOverflow(td.num)

        eq(check.ToDatetimeString(UTC), td.check, "failed SubMonthsNoOverflow, index " + td.index)
    }
}

func Test_SubMonth(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2024-05-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2021-05-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubMonth()

        eq(check.ToDatetimeString(UTC), td.check, "failed SubMonth, index " + td.index)
    }
}

func Test_SubMonthNoOverflow(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2024-05-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2021-05-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubMonthNoOverflow()

        eq(check.ToDatetimeString(UTC), td.check, "failed SubMonthNoOverflow, index " + td.index)
    }
}

func Test_AddMonths(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            num: 1,
            check: "2024-07-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            num: 2,
            check: "2021-08-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddMonths(td.num)

        eq(check.ToDatetimeString(UTC), td.check, "failed AddMonths, index " + td.index)
    }
}

func Test_AddMonthsNoOverflow(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            num: 1,
            check: "2024-07-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            num: 2,
            check: "2021-08-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddMonthsNoOverflow(td.num)

        eq(check.ToDatetimeString(UTC), td.check, "failed AddMonthsNoOverflow, index " + td.index)
    }
}

func Test_AddMonth(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2024-07-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2021-07-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddMonth()

        eq(check.ToDatetimeString(UTC), td.check, "failed AddMonth, index " + td.index)
    }
}

func Test_AddMonthNoOverflow(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2024-07-06 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2021-07-06 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddMonthNoOverflow()

        eq(check.ToDatetimeString(UTC), td.check, "failed AddMonthNoOverflow, index " + td.index)
    }
}

func Test_SubWeekdays(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            num: 1,
            check: "2024-05-30 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            num: 2,
            check: "2021-05-23 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubWeekdays(td.num)

        eq(check.ToDatetimeString(UTC), td.check, "failed SubWeekdays, index " + td.index)
    }
}

func Test_SubWeekday(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2024-05-30 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2021-05-30 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubWeekday()

        eq(check.ToDatetimeString(UTC), td.check, "failed SubWeekday, index " + td.index)
    }
}

func Test_AddWeekdays(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            num: 1,
            check: "2024-06-13 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            num: 2,
            check: "2021-06-20 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddWeekdays(td.num)

        eq(check.ToDatetimeString(UTC), td.check, "failed AddWeekdays, index " + td.index)
    }
}

func Test_AddWeekday(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2024-06-13 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2021-06-13 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddWeekday()

        eq(check.ToDatetimeString(UTC), td.check, "failed AddWeekday, index " + td.index)
    }
}

func Test_SubDays(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            num: 1,
            check: "2024-06-05 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            num: 2,
            check: "2021-06-04 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubDays(td.num)

        eq(check.ToDatetimeString(UTC), td.check, "failed SubDays, index " + td.index)
    }
}

func Test_SubDay(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2024-06-05 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2021-06-05 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubDay()

        eq(check.ToDatetimeString(UTC), td.check, "failed SubDay, index " + td.index)
    }
}

func Test_AddDays(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            num: 1,
            check: "2024-06-07 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            num: 2,
            check: "2021-06-08 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddDays(td.num)

        eq(check.ToDatetimeString(UTC), td.check, "failed AddDays, index " + td.index)
    }
}

func Test_AddDay(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2024-06-07 21:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2021-06-07 21:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddDay()

        eq(check.ToDatetimeString(UTC), td.check, "failed AddDay, index " + td.index)
    }
}

func Test_SubHours(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            num: 1,
            check: "2024-06-06 20:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            num: 2,
            check: "2021-06-06 19:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubHours(td.num)

        eq(check.ToDatetimeString(UTC), td.check, "failed SubHours, index " + td.index)
    }
}

func Test_SubHour(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2024-06-06 20:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2021-06-06 20:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubHour()

        eq(check.ToDatetimeString(UTC), td.check, "failed SubHour, index " + td.index)
    }
}

func Test_AddHours(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            num: 1,
            check: "2024-06-06 22:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            num: 2,
            check: "2021-06-06 23:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddHours(td.num)

        eq(check.ToDatetimeString(UTC), td.check, "failed AddHours, index " + td.index)
    }
}

func Test_AddHour(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2024-06-06 22:15:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2021-06-06 22:15:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddHour()

        eq(check.ToDatetimeString(UTC), td.check, "failed AddHour, index " + td.index)
    }
}

func Test_SubMinutes(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            num: 1,
            check: "2024-06-06 21:14:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            num: 2,
            check: "2021-06-06 21:13:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubMinutes(td.num)

        eq(check.ToDatetimeString(UTC), td.check, "failed SubMinutes, index " + td.index)
    }
}

func Test_SubMinute(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2024-06-06 21:14:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2021-06-06 21:14:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubMinute()

        eq(check.ToDatetimeString(UTC), td.check, "failed SubMinute, index " + td.index)
    }
}

func Test_AddMinutes(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            num: 1,
            check: "2024-06-06 21:16:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            num: 2,
            check: "2021-06-06 21:17:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddMinutes(td.num)

        eq(check.ToDatetimeString(UTC), td.check, "failed AddMinutes, index " + td.index)
    }
}

func Test_AddMinute(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2024-06-06 21:16:12",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2021-06-06 21:16:12",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddMinute()

        eq(check.ToDatetimeString(UTC), td.check, "failed AddMinute, index " + td.index)
    }
}

func Test_SubSeconds(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            num: 1,
            check: "2024-06-06 21:15:11",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            num: 2,
            check: "2021-06-06 21:15:10",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubSeconds(td.num)

        eq(check.ToDatetimeString(UTC), td.check, "failed SubSeconds, index " + td.index)
    }
}

func Test_SubSecond(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2024-06-06 21:15:11",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2021-06-06 21:15:11",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubSecond()

        eq(check.ToDatetimeString(UTC), td.check, "failed SubSecond, index " + td.index)
    }
}

func Test_AddSeconds(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            num: 1,
            check: "2024-06-06 21:15:13",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            num: 2,
            check: "2021-06-06 21:15:14",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddSeconds(td.num)

        eq(check.ToDatetimeString(UTC), td.check, "failed AddSeconds, index " + td.index)
    }
}

func Test_AddSecond(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "2024-06-06 21:15:12",
            check: "2024-06-06 21:15:13",
        },
        {
            index: "index-2",
            date: "2021-06-06 21:15:12",
            check: "2021-06-06 21:15:13",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddSecond()

        eq(check.ToDatetimeString(UTC), td.check, "failed AddSecond, index " + td.index)
    }
}

func Test_SubMilliseconds(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "20240606211512.666",
            num: 1,
            check: "2024-06-06 21:15:12.665",
        },
        {
            index: "index-2",
            date: "20210606211512.666",
            num: 2,
            check: "2021-06-06 21:15:12.664",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubMilliseconds(td.num)

        eq(check.ToLayoutString(DatetimeMilliFormat, UTC), td.check, "failed SubMilliseconds, index " + td.index)
    }
}

func Test_SubMillisecond(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "20240606211512.666",
            check: "2024-06-06 21:15:12.665",
        },
        {
            index: "index-2",
            date: "20210606211512.666",
            check: "2021-06-06 21:15:12.665",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubMillisecond()

        eq(check.ToLayoutString(DatetimeMilliFormat, UTC), td.check, "failed SubMillisecond, index " + td.index)
    }
}

func Test_AddMilliseconds(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "20240606211512.666",
            num: 1,
            check: "2024-06-06 21:15:12.667",
        },
        {
            index: "index-2",
            date: "20210606211512.666",
            num: 2,
            check: "2021-06-06 21:15:12.668",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddMilliseconds(td.num)

        eq(check.ToLayoutString(DatetimeMilliFormat, UTC), td.check, "failed AddMilliseconds, index " + td.index)
    }
}

func Test_AddMillisecond(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "20240606211512.666",
            check: "2024-06-06 21:15:12.667",
        },
        {
            index: "index-2",
            date: "20210606211512.666",
            check: "2021-06-06 21:15:12.667",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddMillisecond()

        eq(check.ToLayoutString(DatetimeMilliFormat, UTC), td.check, "failed AddMillisecond, index " + td.index)
    }
}

func Test_SubMicroseconds(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "20240606211512.666666",
            num: 1,
            check: "2024-06-06 21:15:12.666665",
        },
        {
            index: "index-2",
            date: "20210606211512.666666",
            num: 2,
            check: "2021-06-06 21:15:12.666664",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubMicroseconds(td.num)

        eq(check.ToLayoutString(DatetimeMicroFormat, UTC), td.check, "failed SubMicroseconds, index " + td.index)
    }
}

func Test_SubMicrosecond(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "20240606211512.666666",
            check: "2024-06-06 21:15:12.666665",
        },
        {
            index: "index-2",
            date: "20210606211512.666666",
            check: "2021-06-06 21:15:12.666665",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubMicrosecond()

        eq(check.ToLayoutString(DatetimeMicroFormat, UTC), td.check, "failed SubMicrosecond, index " + td.index)
    }
}

func Test_AddMicroseconds(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "20240606211512.666666",
            num: 1,
            check: "2024-06-06 21:15:12.666667",
        },
        {
            index: "index-2",
            date: "20210606211512.666666",
            num: 2,
            check: "2021-06-06 21:15:12.666668",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddMicroseconds(td.num)

        eq(check.ToLayoutString(DatetimeMicroFormat, UTC), td.check, "failed AddMicroseconds, index " + td.index)
    }
}

func Test_AddMicrosecond(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "20240606211512.666666",
            check: "2024-06-06 21:15:12.666667",
        },
        {
            index: "index-2",
            date: "20210606211512.666666",
            check: "2021-06-06 21:15:12.666667",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddMicrosecond()

        eq(check.ToLayoutString(DatetimeMicroFormat, UTC), td.check, "failed AddMicrosecond, index " + td.index)
    }
}

func Test_SubNanoseconds(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "20240606211512.666666666",
            num: 1,
            check: "2024-06-06 21:15:12.666666665",
        },
        {
            index: "index-2",
            date: "20210606211512.666666666",
            num: 2,
            check: "2021-06-06 21:15:12.666666664",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubNanoseconds(td.num)

        eq(check.ToLayoutString(DatetimeNanoFormat, UTC), td.check, "failed SubNanoseconds, index " + td.index)
    }
}

func Test_SubNanosecond(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "20240606211512.666666666",
            check: "2024-06-06 21:15:12.666666665",
        },
        {
            index: "index-2",
            date: "20210606211512.666666666",
            check: "2021-06-06 21:15:12.666666665",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).SubNanosecond()

        eq(check.ToLayoutString(DatetimeNanoFormat, UTC), td.check, "failed SubNanosecond, index " + td.index)
    }
}

func Test_AddNanoseconds(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        num uint
        check string
    } {
        {
            index: "index-1",
            date: "20240606211512.666666666",
            num: 1,
            check: "2024-06-06 21:15:12.666666667",
        },
        {
            index: "index-2",
            date: "20210606211512.666666666",
            num: 2,
            check: "2021-06-06 21:15:12.666666668",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddNanoseconds(td.num)

        eq(check.ToLayoutString(DatetimeNanoFormat, UTC), td.check, "failed AddNanoseconds, index " + td.index)
    }
}

func Test_AddNanosecond(t *testing.T) {
    eq := assertEqualT(t)

    tests := []struct {
        index string
        date string
        check string
    } {
        {
            index: "index-1",
            date: "20240606211512.666666666",
            check: "2024-06-06 21:15:12.666666667",
        },
        {
            index: "index-2",
            date: "20210606211512.666666666",
            check: "2021-06-06 21:15:12.666666667",
        },
    }

    for _, td := range tests {
        check := Parse(td.date).AddNanosecond()

        eq(check.ToLayoutString(DatetimeNanoFormat, UTC), td.check, "failed AddNanosecond, index " + td.index)
    }
}

