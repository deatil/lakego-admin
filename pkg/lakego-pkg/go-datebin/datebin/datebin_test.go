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

func Test_MarshalBinary(t *testing.T) {
    eq := assertEqualT(t)

    date := "2024-06-05 21:15:12"

    marshaled, err := Parse(date, UTC).MarshalBinary()
    if err != nil {
        t.Fatal(err)
    }

    var tt Datebin
    err = tt.UnmarshalBinary(marshaled)
    if err != nil {
        t.Fatal(err)
    }

    eq(tt.ToDatetimeString(UTC), date, "failed MarshalBinary")
}

func Test_GobEncode(t *testing.T) {
    eq := assertEqualT(t)

    date := "2024-06-05 21:15:12"

    marshaled, err := Parse(date, UTC).GobEncode()
    if err != nil {
        t.Fatal(err)
    }

    var tt Datebin
    err = tt.GobDecode(marshaled)
    if err != nil {
        t.Fatal(err)
    }

    eq(tt.ToDatetimeString(), date, "failed GobEncode")
}
