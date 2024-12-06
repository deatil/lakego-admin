package test

import (
    "testing"
    "reflect"
)

func AssertEqualT(t *testing.T) func(any, any, string) {
    return func(actual any, expected any, msg string) {
        if !reflect.DeepEqual(actual, expected) {
            t.Errorf("Failed %s: actual: %v, expected: %v", msg, actual, expected)
        }
    }
}

func AssertNotEqualT(t *testing.T) func(any, any, string) {
    return func(actual any, expected any, msg string) {
        if reflect.DeepEqual(actual, expected) {
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

func AssertNotErrorT(t *testing.T) func(error, string) {
    return func(err error, msg string) {
        if err != nil {
            t.Errorf("Failed %s: error: %+v", msg, err)
        }
    }
}

func AssertNotErrorNilT(t *testing.T) func(error, string) {
    return func(err error, msg string) {
        if err == nil {
            t.Errorf("Failed %s: error: error is nil", msg)
        }
    }
}

func AssertEmptyT(t *testing.T) func(any, string) {
    return func(data any, msg string) {
        if !isEmpty(data) {
            t.Errorf("Failed %s: error: data not empty", msg)
        }
    }
}

func AssertNotEmptyT(t *testing.T) func(any, string) {
    return func(data any, msg string) {
        if isEmpty(data) {
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

func AssertNotBoolT(t *testing.T) func(bool, string) {
    return func(data bool, msg string) {
        if data {
            t.Errorf("Failed %s: error: data is true", msg)
        }
    }
}

func AssertFalseT(t *testing.T) func(bool, string) {
    return func(data bool, msg string) {
        if data {
            t.Errorf("Failed %s: error: data not false", msg)
        }
    }
}

func AssertTrueT(t *testing.T) func(bool, string) {
    return func(data bool, msg string) {
        if !data {
            t.Errorf("Failed %s: error: data is false", msg)
        }
    }
}

// 为空
func isEmpty(x any) bool {
    rt := reflect.TypeOf(x)
    if rt == nil {
        return true
    }

    rv := reflect.ValueOf(x)
    switch rv.Kind() {
        case reflect.Array,
            reflect.Map,
            reflect.Slice:
            return rv.Len() == 0
    }

    return reflect.DeepEqual(x, reflect.Zero(rt).Interface())
}

func MustPanic(t *testing.T, msg string, f func()) {
    t.Helper()

    defer func() {
        t.Helper()

        err := recover()

        if err == nil {
            t.Errorf("function did not panic for %q", msg)
        }
    }()

    f()
}
