package test

import (
    "testing"
    "reflect"
)

func AssertT(t *testing.T) func(any, any, string) {
    return func(actual any, expected any, msg string) {
        if !reflect.DeepEqual(actual, expected) {
            t.Errorf("Failed %s: actual: %v, expected: %v", msg, actual, expected)
        }
    }
}

func AssertErrorT(t *testing.T) func(error, string) {
    return func(err error, msg string) {
        if err != nil {
            t.Errorf("Failed %s: error: %+v", msg, err)
        }
    }
}

func AssertEmptyT(t *testing.T) func(string, string) {
    return func(data string, msg string) {
        if data == "" {
            t.Errorf("Failed %s: error: data empty", msg)
        }
    }
}

func AssertBoolT(t *testing.T) func(bool, string) {
    return func(data bool, msg string) {
        if !data {
            t.Errorf("Failed %s: error: data not true", msg)
        }
    }
}
