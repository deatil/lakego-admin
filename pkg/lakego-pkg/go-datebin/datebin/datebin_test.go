package datebin

import (
    "time"
    "errors"
    "testing"
    "reflect"
)

func assertErrorT(t *testing.T) func(error, string) {
    return func(err error, msg string) {
        if err != nil {
            t.Errorf("Failed %s: error: %+v", msg, err)
        }
    }
}

func assertEqualT(t *testing.T) func(any, any, string) {
    return func(actual any, expected any, msg string) {
        if !reflect.DeepEqual(actual, expected) {
            t.Errorf("Failed %s: actual: %v, expected: %v", msg, actual, expected)
        }
    }
}

func Test_Now(t *testing.T) {
    eq := assertEqualT(t)

    actual1 := Now().ToDatetimeString()
    expected1 := time.Now().Format(DatetimeFormat)

    eq(actual1, expected1, "failed now time is error")

    actual2 := Now(Local).ToDatetimeString()
    expected2 := time.Now().In(time.Local).Format(DatetimeFormat)

    eq(actual2, expected2, "failed now time Local is error")
}

func Test_With(t *testing.T) {
    eq := assertEqualT(t)

    tt := time.Now()
    weekday := time.Friday
    loc := time.Local
    errs := []error{
        errors.New("test error"),
    }

    d := NewDatebin()
    d = d.WithTime(tt).
        WithWeekStartAt(weekday).
        WithLocation(loc).
        WithErrors(errs)

    eq(d.time, tt, "failed time")
    eq(d.weekStartAt, weekday, "failed weekStartAt")
    eq(d.loc, loc, "failed loc")
    eq(d.Errors, errs, "failed Errors")
}

func Test_Get(t *testing.T) {
    eq := assertEqualT(t)

    tt := time.Now()
    weekday := time.Friday
    loc := time.Local
    errs := []error{
        errors.New("test error"),
    }

    d := &Datebin{
        time: tt,
        weekStartAt: weekday,
        loc: loc,
        Errors: errs,
    }

    eq(d.GetTime(), tt, "failed time")
    eq(d.GetWeekStartAt(), weekday, "failed weekStartAt")
    eq(d.GetLocation(), loc, "failed loc")
    eq(d.GetErrors(), errs, "failed Errors")
}
