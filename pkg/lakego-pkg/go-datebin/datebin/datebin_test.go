package datebin

import (
    "testing"
    "time"
)

func assertT(t *testing.T) func(string, string, string) {
    return func(actual string, expected string, msg string) {
        actualStr := actual
        if actualStr != expected {
            t.Errorf("Failed %s: actual: %v, expected: %v", msg, actualStr, expected)
        }
    }
}

func Test_Now(t *testing.T) {
    actual1 := Now().ToDatetimeString()
    expected1 := time.Now().Format(DatetimeFormat)
    if expected1 != actual1 {
        t.Errorf("failed now time is error")
    }

    actual2 := Now(Local).ToDatetimeString()
    expected2 := time.Now().In(time.Local).Format(DatetimeFormat)
    if expected2 != actual2 {
        t.Errorf("failed now time Local is error")
    }
}
