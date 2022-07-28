package datebin

import (
    "testing"
    "time"
)

func TestDatebin_Now(t *testing.T) {
    actual1 := Now().ToDatetimeString()
    expected1 := time.Now().Format(DatetimeFormat)
    if expected1 != actual1 {
        t.Errorf("failed now time is error")
    }

    actual2 := Now(LocLocal).ToDatetimeString()
    expected2 := time.Now().In(time.Local).Format(DatetimeFormat)
    if expected2 != actual2 {
        t.Errorf("failed now time Local is error")
    }
}
