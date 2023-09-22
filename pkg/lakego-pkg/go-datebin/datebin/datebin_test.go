package datebin

import (
    "testing"
    "time"
)

func assertErrorT(t *testing.T) func(error, string) {
    return func(err error, msg string) {
        if err != nil {
            t.Errorf("Failed %s: error: %+v", msg, err)
        }
    }
}

func assertEqualT(t *testing.T) func(string, string, string) {
    return func(actual string, expected string, msg string) {
        actualStr := actual
        if actualStr != expected {
            t.Errorf("Failed %s: actual: %v, expected: %v", msg, actualStr, expected)
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
