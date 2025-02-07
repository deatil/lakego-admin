package test

import (
    "time"
)

// Conditionf uses a Comparison to assert a complex condition.
func Conditionf(t TestingT, comp Comparison, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return Condition(t, comp, append([]any{msg}, args...)...)
}

// Containsf asserts that the specified string, list(array, slice...) or map contains the
// specified substring or element.
//
//	test.Containsf(t, "Hello World", "World", "error message %s", "formatted")
//	test.Containsf(t, ["Hello", "World"], "World", "error message %s", "formatted")
//	test.Containsf(t, {"Hello": "World"}, "Hello", "error message %s", "formatted")
func Containsf(t TestingT, s any, contains any, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return Contains(t, s, contains, append([]any{msg}, args...)...)
}

// Emptyf asserts that the specified object is empty.  I.e. nil, "", false, 0 or either
// a slice or a channel with len == 0.
//
//	test.Emptyf(t, obj, "error message %s", "formatted")
func Emptyf(t TestingT, object any, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return Empty(t, object, append([]any{msg}, args...)...)
}

// Equalf asserts that two objects are equal.
//
//	test.Equalf(t, 123, 123, "error message %s", "formatted")
//
// Pointer variable equality is determined based on the equality of the
// referenced values (as opposed to the memory addresses). Function equality
// cannot be determined and will always fail.
func Equalf(t TestingT, expected any, actual any, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return Equal(t, expected, actual, append([]any{msg}, args...)...)
}

// EqualErrorf asserts that a function returned an error (i.e. not `nil`)
// and that it is equal to the provided error.
//
//	actualObj, err := SomeFunction()
//	test.EqualErrorf(t, err,  expectedErrorString, "error message %s", "formatted")
func EqualErrorf(t TestingT, theError error, errString string, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return EqualError(t, theError, errString, append([]any{msg}, args...)...)
}

// EqualExportedValuesf asserts that the types of two objects are equal and their public
// fields are also equal. This is useful for comparing structs that have private fields
// that could potentially differ.
//
//	 type S struct {
//		Exported     	int
//		notExported   	int
//	 }
//	 test.EqualExportedValuesf(t, S{1, 2}, S{1, 3}, "error message %s", "formatted") => true
//	 test.EqualExportedValuesf(t, S{1, 2}, S{2, 3}, "error message %s", "formatted") => false
func EqualExportedValuesf(t TestingT, expected any, actual any, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return EqualExportedValues(t, expected, actual, append([]any{msg}, args...)...)
}

// EqualValuesf asserts that two objects are equal or convertible to the larger
// type and equal.
//
//	test.EqualValuesf(t, uint32(123), int32(123), "error message %s", "formatted")
func EqualValuesf(t TestingT, expected any, actual any, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return EqualValues(t, expected, actual, append([]any{msg}, args...)...)
}

// Errorf asserts that a function returned an error (i.e. not `nil`).
//
//	  actualObj, err := SomeFunction()
//	  if test.Errorf(t, err, "error message %s", "formatted") {
//		   test.Equal(t, expectedErrorf, err)
//	  }
func Errorf(t TestingT, err error, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return Error(t, err, append([]any{msg}, args...)...)
}

// ErrorAsf asserts that at least one of the errors in err's chain matches target, and if so, sets target to that error value.
// This is a wrapper for errors.As.
func ErrorAsf(t TestingT, err error, target any, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return ErrorAs(t, err, target, append([]any{msg}, args...)...)
}

// ErrorContainsf asserts that a function returned an error (i.e. not `nil`)
// and that the error contains the specified substring.
//
//	actualObj, err := SomeFunction()
//	test.ErrorContainsf(t, err,  expectedErrorSubString, "error message %s", "formatted")
func ErrorContainsf(t TestingT, theError error, contains string, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return ErrorContains(t, theError, contains, append([]any{msg}, args...)...)
}

// ErrorIsf asserts that at least one of the errors in err's chain matches target.
// This is a wrapper for errors.Is.
func ErrorIsf(t TestingT, err error, target error, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return ErrorIs(t, err, target, append([]any{msg}, args...)...)
}

// Exactlyf asserts that two objects are equal in value and type.
//
//	test.Exactlyf(t, int32(123), int64(123), "error message %s", "formatted")
func Exactlyf(t TestingT, expected any, actual any, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return Exactly(t, expected, actual, append([]any{msg}, args...)...)
}

// Failf reports a failure through
func Failf(t TestingT, failureMessage string, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return Fail(t, failureMessage, append([]any{msg}, args...)...)
}

// FailNowf fails test
func FailNowf(t TestingT, failureMessage string, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return FailNow(t, failureMessage, append([]any{msg}, args...)...)
}

// Falsef asserts that the specified value is false.
//
//	test.Falsef(t, myBool, "error message %s", "formatted")
func Falsef(t TestingT, value bool, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return False(t, value, append([]any{msg}, args...)...)
}

// IsTypef asserts that the specified objects are of the same type.
func IsTypef(t TestingT, expectedType any, object any, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return IsType(t, expectedType, object, append([]any{msg}, args...)...)
}

// Nilf asserts that the specified object is nil.
//
//	test.Nilf(t, err, "error message %s", "formatted")
func Nilf(t TestingT, object any, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return Nil(t, object, append([]any{msg}, args...)...)
}

// NoErrorf asserts that a function returned no error (i.e. `nil`).
//
//	  actualObj, err := SomeFunction()
//	  if test.NoErrorf(t, err, "error message %s", "formatted") {
//		   test.Equal(t, expectedObj, actualObj)
//	  }
func NoErrorf(t TestingT, err error, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return NoError(t, err, append([]any{msg}, args...)...)
}
// NotContainsf asserts that the specified string, list(array, slice...) or map does NOT contain the
// specified substring or element.
//
//	test.NotContainsf(t, "Hello World", "Earth", "error message %s", "formatted")
//	test.NotContainsf(t, ["Hello", "World"], "Earth", "error message %s", "formatted")
//	test.NotContainsf(t, {"Hello": "World"}, "Earth", "error message %s", "formatted")
func NotContainsf(t TestingT, s any, contains any, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return NotContains(t, s, contains, append([]any{msg}, args...)...)
}

// NotEmptyf asserts that the specified object is NOT empty.  I.e. not nil, "", false, 0 or either
// a slice or a channel with len == 0.
//
//	if test.NotEmptyf(t, obj, "error message %s", "formatted") {
//	  test.Equal(t, "two", obj[1])
//	}
func NotEmptyf(t TestingT, object any, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return NotEmpty(t, object, append([]any{msg}, args...)...)
}

// NotEqualf asserts that the specified values are NOT equal.
//
//	test.NotEqualf(t, obj1, obj2, "error message %s", "formatted")
//
// Pointer variable equality is determined based on the equality of the
// referenced values (as opposed to the memory addresses).
func NotEqualf(t TestingT, expected any, actual any, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return NotEqual(t, expected, actual, append([]any{msg}, args...)...)
}

// NotEqualValuesf asserts that two objects are not equal even when converted to the same type
//
//	test.NotEqualValuesf(t, obj1, obj2, "error message %s", "formatted")
func NotEqualValuesf(t TestingT, expected any, actual any, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return NotEqualValues(t, expected, actual, append([]any{msg}, args...)...)
}

// NotErrorAsf asserts that none of the errors in err's chain matches target,
// but if so, sets target to that error value.
func NotErrorAsf(t TestingT, err error, target any, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return NotErrorAs(t, err, target, append([]any{msg}, args...)...)
}

// NotErrorIsf asserts that none of the errors in err's chain matches target.
// This is a wrapper for errors.Is.
func NotErrorIsf(t TestingT, err error, target error, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return NotErrorIs(t, err, target, append([]any{msg}, args...)...)
}

// NotNilf asserts that the specified object is not nil.
//
//	test.NotNilf(t, err, "error message %s", "formatted")
func NotNilf(t TestingT, object any, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return NotNil(t, object, append([]any{msg}, args...)...)
}

// NotPanicsf asserts that the code inside the specified PanicTestFunc does NOT panic.
//
//	test.NotPanicsf(t, func(){ RemainCalm() }, "error message %s", "formatted")
func NotPanicsf(t TestingT, f PanicTestFunc, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return NotPanics(t, f, append([]any{msg}, args...)...)
}

// NotSamef asserts that two pointers do not reference the same object.
//
//	test.NotSamef(t, ptr1, ptr2, "error message %s", "formatted")
//
// Both arguments must be pointer variables. Pointer variable sameness is
// determined based on the equality of both type and value.
func NotSamef(t TestingT, expected any, actual any, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return NotSame(t, expected, actual, append([]any{msg}, args...)...)
}

// NotSubsetf asserts that the specified list(array, slice...) or map does NOT
// contain all elements given in the specified subset list(array, slice...) or
// map.
//
//	test.NotSubsetf(t, [1, 3, 4], [1, 2], "error message %s", "formatted")
//	test.NotSubsetf(t, {"x": 1, "y": 2}, {"z": 3}, "error message %s", "formatted")
func NotSubsetf(t TestingT, list any, subset any, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return NotSubset(t, list, subset, append([]any{msg}, args...)...)
}

// NotZerof asserts that i is not the zero value for its type.
func NotZerof(t TestingT, i any, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return NotZero(t, i, append([]any{msg}, args...)...)
}

// Panicsf asserts that the code inside the specified PanicTestFunc panics.
//
//	test.Panicsf(t, func(){ GoCrazy() }, "error message %s", "formatted")
func Panicsf(t TestingT, f PanicTestFunc, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return Panics(t, f, append([]any{msg}, args...)...)
}

// PanicsWithErrorf asserts that the code inside the specified PanicTestFunc
// panics, and that the recovered panic value is an error that satisfies the
// EqualError comparison.
//
//	test.PanicsWithErrorf(t, "crazy error", func(){ GoCrazy() }, "error message %s", "formatted")
func PanicsWithErrorf(t TestingT, errString string, f PanicTestFunc, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return PanicsWithError(t, errString, f, append([]any{msg}, args...)...)
}

// PanicsWithValuef asserts that the code inside the specified PanicTestFunc panics, and that
// the recovered panic value equals the expected panic value.
//
//	test.PanicsWithValuef(t, "crazy error", func(){ GoCrazy() }, "error message %s", "formatted")
func PanicsWithValuef(t TestingT, expected any, f PanicTestFunc, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return PanicsWithValue(t, expected, f, append([]any{msg}, args...)...)
}

// Samef asserts that two pointers reference the same object.
//
//	test.Samef(t, ptr1, ptr2, "error message %s", "formatted")
//
// Both arguments must be pointer variables. Pointer variable sameness is
// determined based on the equality of both type and value.
func Samef(t TestingT, expected any, actual any, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return Same(t, expected, actual, append([]any{msg}, args...)...)
}

// Subsetf asserts that the specified list(array, slice...) or map contains all
// elements given in the specified subset list(array, slice...) or map.
//
//	test.Subsetf(t, [1, 2, 3], [1, 2], "error message %s", "formatted")
//	test.Subsetf(t, {"x": 1, "y": 2}, {"x": 1}, "error message %s", "formatted")
func Subsetf(t TestingT, list any, subset any, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return Subset(t, list, subset, append([]any{msg}, args...)...)
}

// Truef asserts that the specified value is true.
//
//	test.Truef(t, myBool, "error message %s", "formatted")
func Truef(t TestingT, value bool, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return True(t, value, append([]any{msg}, args...)...)
}

// Zerof asserts that i is the zero value for its type.
func Zerof(t TestingT, i any, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return Zero(t, i, append([]any{msg}, args...)...)
}

// WithinDurationf asserts that the two times are within duration delta of each other.
//
//	test.WithinDurationf(t, time.Now(), time.Now(), 10*time.Second, "error message %s", "formatted")
func WithinDurationf(t TestingT, expected time.Time, actual time.Time, delta time.Duration, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return WithinDuration(t, expected, actual, delta, append([]any{msg}, args...)...)
}

// WithinRangef asserts that a time is within a time range (inclusive).
//
//	test.WithinRangef(t, time.Now(), time.Now().Add(-time.Second), time.Now().Add(time.Second), "error message %s", "formatted")
func WithinRangef(t TestingT, actual time.Time, start time.Time, end time.Time, msg string, args ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return WithinRange(t, actual, start, end, append([]any{msg}, args...)...)
}




