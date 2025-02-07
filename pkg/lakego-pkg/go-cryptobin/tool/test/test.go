package test

import (
    "testing"
)

func AssertEqualT(t *testing.T) func(any, any, string) {
    return func(actual any, expected any, msg string) {
        Equal(t, actual, expected, msg)
    }
}

func AssertNotEqualT(t *testing.T) func(any, any, string) {
    return func(actual any, expected any, msg string) {
        NotEqual(t, actual, expected, msg)
    }
}

func AssertErrorT(t *testing.T) func(error, string) {
    return func(err error, msg string) {
        Error(t, err, msg)
    }
}

func AssertNoErrorT(t *testing.T) func(error, string) {
    return func(err error, msg string) {
        NoError(t, err, msg)
    }
}

func AssertEmptyT(t *testing.T) func(any, string) {
    return func(data any, msg string) {
        Empty(t, data, msg)
    }
}

func AssertNotEmptyT(t *testing.T) func(any, string) {
    return func(data any, msg string) {
        NotEmpty(t, data, msg)
    }
}

func AssertTrueT(t *testing.T) func(bool, string) {
    return func(data bool, msg string) {
        True(t, data, msg)
    }
}

func AssertFalseT(t *testing.T) func(bool, string) {
    return func(data bool, msg string) {
        False(t, data, msg)
    }
}
