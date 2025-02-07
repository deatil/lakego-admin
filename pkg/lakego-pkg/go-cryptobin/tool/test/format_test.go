package test

import (
    "errors"
    "testing"
)

func Test_ErrorContainsf(t *testing.T) {
    mockT := new(testing.T)

    // start with a nil error
    var err error
    False(t, ErrorContainsf(mockT, err, "", ""),
        "ErrorContainsf should return false for nil arg")

    // now set an error
    err = errors.New("some error: another error")
    False(t, ErrorContainsf(mockT, err, "bad error", "bad"),
        "ErrorContainsf should return false for different error string")
    True(t, ErrorContainsf(mockT, err, "some error", "some"),
        "ErrorContainsf should return true")
    True(t, ErrorContainsf(mockT, err, "another error", "another"),
        "ErrorContainsf should return true")
}

func Test_Conditionf(t *testing.T) {
    mockT := new(testing.T)

    if !Conditionf(mockT, func() bool { return true }, "Truth") {
        t.Error("Conditionf should return true")
    }

    if Conditionf(mockT, func() bool { return false }, "Lie") {
        t.Error("Conditionf should return false")
    }

}
