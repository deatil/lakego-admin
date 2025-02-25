package test

import (
    "fmt"
    "time"
    "bytes"
    "bufio"
    "errors"
    "strings"
    "testing"
    "reflect"
    "runtime"
    "unicode"
    "unicode/utf8"
    "runtime/debug"
)

// TestingT is an interface wrapper around *testing.T
type TestingT interface {
    Errorf(format string, args ...any)
}

type PanicTestFunc func()

// ComparisonAssertionFunc is a common function prototype when comparing two values.  Can be useful
// for table driven tests.
type ComparisonAssertionFunc func(TestingT, any, any, ...any) bool

// ValueAssertionFunc is a common function prototype when validating a single value.  Can be useful
// for table driven tests.
type ValueAssertionFunc func(TestingT, any, ...any) bool

// BoolAssertionFunc is a common function prototype when validating a bool value.  Can be useful
// for table driven tests.
type BoolAssertionFunc func(TestingT, bool, ...any) bool

// ErrorAssertionFunc is a common function prototype when validating an error value.  Can be useful
// for table driven tests.
type ErrorAssertionFunc func(TestingT, error, ...any) bool

// PanicAssertionFunc is a common function prototype when validating a panic value.  Can be useful
// for table driven tests.
type PanicAssertionFunc = func(t TestingT, f PanicTestFunc, msgAndArgs ...any) bool

// Comparison is a custom function that returns true on success and false on failure
type Comparison func() (success bool)

type tHelper = interface {
    Helper()
}

type failNower interface {
    FailNow()
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

// ObjectsAreEqual determines if two objects are considered equal.
func ObjectsAreEqual(expected, actual any) bool {
    if expected == nil || actual == nil {
        return expected == actual
    }

    exp, ok := expected.([]byte)
    if !ok {
        return reflect.DeepEqual(expected, actual)
    }

    act, ok := actual.([]byte)
    if !ok {
        return false
    }

    if exp == nil || act == nil {
        return exp == nil && act == nil
    }

    return bytes.Equal(exp, act)
}

// ObjectsAreEqualValues gets whether two objects are equal, or if their
// values are equal.
func ObjectsAreEqualValues(expected, actual any) bool {
    if ObjectsAreEqual(expected, actual) {
        return true
    }

    expectedValue := reflect.ValueOf(expected)
    actualValue := reflect.ValueOf(actual)
    if !expectedValue.IsValid() || !actualValue.IsValid() {
        return false
    }

    expectedType := expectedValue.Type()
    actualType := actualValue.Type()
    if !expectedType.ConvertibleTo(actualType) {
        return false
    }

    if !isNumericType(expectedType) || !isNumericType(actualType) {
        // Attempt comparison after type conversion
        return reflect.DeepEqual(
            expectedValue.Convert(actualType).Interface(), actual,
        )
    }

    // If BOTH values are numeric, there are chances of false positives due
    // to overflow or underflow. So, we need to make sure to always convert
    // the smaller type to a larger type before comparing.
    if expectedType.Size() >= actualType.Size() {
        return actualValue.Convert(expectedType).Interface() == expected
    }

    return expectedValue.Convert(actualType).Interface() == actual
}

func ObjectsExportedFieldsAreEqual(expected, actual any) bool {
    expectedCleaned := copyExportedFields(expected)
    actualCleaned := copyExportedFields(actual)
    return ObjectsAreEqualValues(expectedCleaned, actualCleaned)
}

// IsType asserts that the specified objects are of the same type.
func IsType(t TestingT, expectedType any, object any, msgAndArgs ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    if !ObjectsAreEqual(reflect.TypeOf(object), reflect.TypeOf(expectedType)) {
        return Fail(t, fmt.Sprintf("Object expected to be of type %v, but was %v", reflect.TypeOf(expectedType), reflect.TypeOf(object)), msgAndArgs...)
    }

    return true
}

// Equal asserts that two objects are equal.
func Equal(t TestingT, expected, actual any, msgAndArgs ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    if err := validateEqualArgs(expected, actual); err != nil {
        return Fail(t, fmt.Sprintf("Invalid operation: %#v == %#v (%s)",
            expected, actual, err), msgAndArgs...)
    }

    if !ObjectsAreEqual(expected, actual) {
        expected, actual = formatUnequalValues(expected, actual)
        return Fail(t, fmt.Sprintf("Not equal: \n"+
            "expected: %s\n"+
            "actual  : %s", expected, actual), msgAndArgs...)
    }

    return true
}

// EqualError asserts that a function returned an error (i.e. not `nil`)
// and that it is equal to the provided error.
func EqualError(t TestingT, theError error, errString string, msgAndArgs ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    if !Error(t, theError, msgAndArgs...) {
        return false
    }

    expected := errString
    actual := theError.Error()

    if expected != actual {
        return Fail(t, fmt.Sprintf("Error message not equal:\n"+
            "expected: %q\n"+
            "actual  : %q", expected, actual), msgAndArgs...)
    }

    return true
}

// EqualValues asserts that two objects are equal or convertible to the larger
// type and equal.
//
//	test.EqualValues(t, uint32(123), int32(123))
func EqualValues(t TestingT, expected, actual interface{}, msgAndArgs ...interface{}) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    if !ObjectsAreEqualValues(expected, actual) {
        expected, actual = formatUnequalValues(expected, actual)
        return Fail(t, fmt.Sprintf("Not equal: \n"+
            "expected: %s\n"+
            "actual  : %s", expected, actual), msgAndArgs...)
    }

    return true
}

// EqualExportedValues asserts that the types of two objects are equal and their public
// fields are also equal. This is useful for comparing structs that have private fields
// that could potentially differ.
//
//	 type S struct {
//		Exported     	int
//		notExported   	int
//	 }
//	 test.EqualExportedValues(t, S{1, 2}, S{1, 3}) => true
//	 test.EqualExportedValues(t, S{1, 2}, S{2, 3}) => false
func EqualExportedValues(t TestingT, expected, actual interface{}, msgAndArgs ...interface{}) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    aType := reflect.TypeOf(expected)
    bType := reflect.TypeOf(actual)

    if aType != bType {
        return Fail(t, fmt.Sprintf("Types expected to match exactly\n\t%v != %v", aType, bType), msgAndArgs...)
    }

    expected = copyExportedFields(expected)
    actual = copyExportedFields(actual)

    if !ObjectsAreEqualValues(expected, actual) {
        expected, actual = formatUnequalValues(expected, actual)
        return Fail(t, fmt.Sprintf("Not equal (comparing only exported fields): \n"+
            "expected: %s\n"+
            "actual  : %s", expected, actual), msgAndArgs...)
    }

    return true
}

// NotEqual asserts that the specified values are NOT equal.
//
//	test.NotEqual(t, obj1, obj2)
func NotEqual(t TestingT, expected, actual any, msgAndArgs ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    if err := validateEqualArgs(expected, actual); err != nil {
        return Fail(t, fmt.Sprintf("Invalid operation: %#v != %#v (%s)",
            expected, actual, err), msgAndArgs...)
    }

    if ObjectsAreEqual(expected, actual) {
        return Fail(t, fmt.Sprintf("Should not be: %#v\n", actual), msgAndArgs...)
    }

    return true

}

// NotEqualValues asserts that two objects are not equal even when converted to the same type
//
//	test.NotEqualValues(t, obj1, obj2)
func NotEqualValues(t TestingT, expected, actual any, msgAndArgs ...interface{}) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    if ObjectsAreEqualValues(expected, actual) {
        return Fail(t, fmt.Sprintf("Should not be: %#v\n", actual), msgAndArgs...)
    }

    return true
}

// Same asserts that two pointers reference the same object.
func Same(t TestingT, expected, actual any, msgAndArgs ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    same, ok := samePointers(expected, actual)
    if !ok {
        return Fail(t, "Both arguments must be pointers", msgAndArgs...)
    }

    if !same {
        return Fail(t, fmt.Sprintf("Not same: \n"+
            "expected: %p %#v\n"+
            "actual  : %p %#v", expected, expected, actual, actual), msgAndArgs...)
    }

    return true
}

// NotSame asserts that two pointers do not reference the same object.
func NotSame(t TestingT, expected, actual any, msgAndArgs ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    same, ok := samePointers(expected, actual)
    if !ok {
        return !(Fail(t, "Both arguments must be pointers", msgAndArgs...))
    }

    if same {
        return Fail(t, fmt.Sprintf(
            "Expected and actual point to the same object: %p %#v",
            expected, expected), msgAndArgs...)
    }

    return true
}

// Exactly asserts that two objects are equal in value and type.
//
//	test.Exactly(t, int32(123), int64(123))
func Exactly(t TestingT, expected, actual interface{}, msgAndArgs ...interface{}) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    aType := reflect.TypeOf(expected)
    bType := reflect.TypeOf(actual)

    if aType != bType {
        return Fail(t, fmt.Sprintf("Types expected to match exactly\n\t%v != %v", aType, bType), msgAndArgs...)
    }

    return Equal(t, expected, actual, msgAndArgs...)

}

// Nil asserts that the specified object is nil.
//
// test.Nil(t, err)
func Nil(t TestingT, object any, msgAndArgs ...any) bool {
    if isNil(object) {
        return true
    }

    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return Fail(t, fmt.Sprintf("Expected nil, but got: %#v", object), msgAndArgs...)
}

// NotNil asserts that the specified object is not nil.
//
// NotNil(t, err)
func NotNil(t TestingT, object any, msgAndArgs ...any) bool {
    if !isNil(object) {
        return true
    }

    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    return Fail(t, "Expected value not to be nil.", msgAndArgs...)
}

// Empty asserts that the specified object is empty.  I.e. nil, "", false, 0 or either
// a slice or a channel with len == 0.
//
//	test.Empty(t, obj)
func Empty(t TestingT, object any, msgAndArgs ...any) bool {
    pass := isEmpty(object)
    if !pass {
        if h, ok := t.(tHelper); ok {
            h.Helper()
        }

        Fail(t, fmt.Sprintf("Should be empty, but was %v", object), msgAndArgs...)
    }

    return pass

}

// NotEmpty asserts that the specified object is NOT empty.  I.e. not nil, "", false, 0 or either
// a slice or a channel with len == 0.
//
//	if test.NotEmpty(t, obj) {
//	  test.Equal(t, "two", obj[1])
//	}
func NotEmpty(t TestingT, object any, msgAndArgs ...any) bool {
    pass := !isEmpty(object)
    if !pass {
        if h, ok := t.(tHelper); ok {
            h.Helper()
        }

        Fail(t, fmt.Sprintf("Should NOT be empty, but was %v", object), msgAndArgs...)
    }

    return pass
}

// getLen tries to get the length of an object.
// It returns (0, false) if impossible.
func getLen(x interface{}) (length int, ok bool) {
    v := reflect.ValueOf(x)

    defer func() {
        ok = recover() == nil
    }()

    return v.Len(), true
}

// Len asserts that the specified object has specific length.
// Len also fails if the object has a type that len() not accept.
//
//	test.Len(t, mySlice, 3)
func Len(t TestingT, object interface{}, length int, msgAndArgs ...interface{}) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    l, ok := getLen(object)
    if !ok {
        return Fail(t, fmt.Sprintf("\"%v\" could not be applied builtin len()", object), msgAndArgs...)
    }

    if l != length {
        return Fail(t, fmt.Sprintf("\"%v\" should have %d item(s), but has %d", object, length, l), msgAndArgs...)
    }

    return true
}

// True asserts that the specified value is true.
//
//	test.True(t, myBool)
func True(t TestingT, value bool, msgAndArgs ...any) bool {
    if !value {
        if h, ok := t.(tHelper); ok {
            h.Helper()
        }

        return Fail(t, "Should be true", msgAndArgs...)
    }

    return true

}

// False asserts that the specified value is false.
//
//	test.False(t, myBool)
func False(t TestingT, value bool, msgAndArgs ...any) bool {
    if value {
        if h, ok := t.(tHelper); ok {
            h.Helper()
        }

        return Fail(t, "Should be false", msgAndArgs...)
    }

    return true
}

// containsElement try loop over the list check if the list includes the element.
// return (false, false) if impossible.
// return (true, false) if element was not found.
// return (true, true) if element was found.
func containsElement(list interface{}, element interface{}) (ok, found bool) {
    listValue := reflect.ValueOf(list)
    listType := reflect.TypeOf(list)
    if listType == nil {
        return false, false
    }

    listKind := listType.Kind()
    defer func() {
        if e := recover(); e != nil {
            ok = false
            found = false
        }
    }()

    if listKind == reflect.String {
        elementValue := reflect.ValueOf(element)
        return true, strings.Contains(listValue.String(), elementValue.String())
    }

    if listKind == reflect.Map {
        mapKeys := listValue.MapKeys()
        for i := 0; i < len(mapKeys); i++ {
            if ObjectsAreEqual(mapKeys[i].Interface(), element) {
                return true, true
            }
        }
        return true, false
    }

    for i := 0; i < listValue.Len(); i++ {
        if ObjectsAreEqual(listValue.Index(i).Interface(), element) {
            return true, true
        }
    }
    return true, false

}

// Contains asserts that the specified string, list(array, slice...) or map contains the
// specified substring or element.
//
//	test.Contains(t, "Hello World", "World")
//	test.Contains(t, ["Hello", "World"], "World")
//	test.Contains(t, {"Hello": "World"}, "Hello")
func Contains(t TestingT, s, contains any, msgAndArgs ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    ok, found := containsElement(s, contains)
    if !ok {
        return Fail(t, fmt.Sprintf("%#v could not be applied builtin len()", s), msgAndArgs...)
    }

    if !found {
        return Fail(t, fmt.Sprintf("%#v does not contain %#v", s, contains), msgAndArgs...)
    }

    return true

}

// NotContains asserts that the specified string, list(array, slice...) or map does NOT contain the
// specified substring or element.
//
//	test.NotContains(t, "Hello World", "Earth")
//	test.NotContains(t, ["Hello", "World"], "Earth")
//	test.NotContains(t, {"Hello": "World"}, "Earth")
func NotContains(t TestingT, s, contains any, msgAndArgs ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    ok, found := containsElement(s, contains)
    if !ok {
        return Fail(t, fmt.Sprintf("%#v could not be applied builtin len()", s), msgAndArgs...)
    }

    if found {
        return Fail(t, fmt.Sprintf("%#v should not contain %#v", s, contains), msgAndArgs...)
    }

    return true

}

// Subset asserts that the specified list(array, slice...) or map contains all
// elements given in the specified subset list(array, slice...) or map.
//
//	test.Subset(t, [1, 2, 3], [1, 2])
//	test.Subset(t, {"x": 1, "y": 2}, {"x": 1})
func Subset(t TestingT, list, subset any, msgAndArgs ...any) (ok bool) {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    if subset == nil {
        return true // we consider nil to be equal to the nil set
    }

    listKind := reflect.TypeOf(list).Kind()
    if listKind != reflect.Array && listKind != reflect.Slice && listKind != reflect.Map {
        return Fail(t, fmt.Sprintf("%q has an unsupported type %s", list, listKind), msgAndArgs...)
    }

    subsetKind := reflect.TypeOf(subset).Kind()
    if subsetKind != reflect.Array && subsetKind != reflect.Slice && listKind != reflect.Map {
        return Fail(t, fmt.Sprintf("%q has an unsupported type %s", subset, subsetKind), msgAndArgs...)
    }

    if subsetKind == reflect.Map && listKind == reflect.Map {
        subsetMap := reflect.ValueOf(subset)
        actualMap := reflect.ValueOf(list)

        for _, k := range subsetMap.MapKeys() {
            ev := subsetMap.MapIndex(k)
            av := actualMap.MapIndex(k)

            if !av.IsValid() {
                return Fail(t, fmt.Sprintf("%#v does not contain %#v", list, subset), msgAndArgs...)
            }
            if !ObjectsAreEqual(ev.Interface(), av.Interface()) {
                return Fail(t, fmt.Sprintf("%#v does not contain %#v", list, subset), msgAndArgs...)
            }
        }

        return true
    }

    subsetList := reflect.ValueOf(subset)
    for i := 0; i < subsetList.Len(); i++ {
        element := subsetList.Index(i).Interface()
        ok, found := containsElement(list, element)
        if !ok {
            return Fail(t, fmt.Sprintf("%#v could not be applied builtin len()", list), msgAndArgs...)
        }

        if !found {
            return Fail(t, fmt.Sprintf("%#v does not contain %#v", list, element), msgAndArgs...)
        }
    }

    return true
}

// NotSubset asserts that the specified list(array, slice...) or map does NOT
// contain all elements given in the specified subset list(array, slice...) or
// map.
//
//	test.NotSubset(t, [1, 3, 4], [1, 2])
//	test.NotSubset(t, {"x": 1, "y": 2}, {"z": 3})
func NotSubset(t TestingT, list, subset any, msgAndArgs ...any) (ok bool) {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    if subset == nil {
        return Fail(t, "nil is the empty set which is a subset of every set", msgAndArgs...)
    }

    listKind := reflect.TypeOf(list).Kind()
    if listKind != reflect.Array && listKind != reflect.Slice && listKind != reflect.Map {
        return Fail(t, fmt.Sprintf("%q has an unsupported type %s", list, listKind), msgAndArgs...)
    }

    subsetKind := reflect.TypeOf(subset).Kind()
    if subsetKind != reflect.Array && subsetKind != reflect.Slice && listKind != reflect.Map {
        return Fail(t, fmt.Sprintf("%q has an unsupported type %s", subset, subsetKind), msgAndArgs...)
    }

    if subsetKind == reflect.Map && listKind == reflect.Map {
        subsetMap := reflect.ValueOf(subset)
        actualMap := reflect.ValueOf(list)

        for _, k := range subsetMap.MapKeys() {
            ev := subsetMap.MapIndex(k)
            av := actualMap.MapIndex(k)

            if !av.IsValid() {
                return true
            }
            if !ObjectsAreEqual(ev.Interface(), av.Interface()) {
                return true
            }
        }

        return Fail(t, fmt.Sprintf("%q is a subset of %q", subset, list), msgAndArgs...)
    }

    subsetList := reflect.ValueOf(subset)
    for i := 0; i < subsetList.Len(); i++ {
        element := subsetList.Index(i).Interface()
        ok, found := containsElement(list, element)
        if !ok {
            return Fail(t, fmt.Sprintf("\"%s\" could not be applied builtin len()", list), msgAndArgs...)
        }

        if !found {
            return true
        }
    }

    return Fail(t, fmt.Sprintf("%q is a subset of %q", subset, list), msgAndArgs...)
}

// Error asserts that a function returned an error (i.e. not `nil`).
func Error(t TestingT, err error, msgAndArgs ...any) bool {
    if err == nil {
        if h, ok := t.(tHelper); ok {
            h.Helper()
        }

        return Fail(t, "An error is expected but got nil.", msgAndArgs...)
    }

    return true
}

// NoError asserts that a function returned no error (i.e. `nil`).
func NoError(t TestingT, err error, msgAndArgs ...any) bool {
    if err != nil {
        if h, ok := t.(tHelper); ok {
            h.Helper()
        }

        return Fail(t, fmt.Sprintf("Received unexpected error:\n%+v", err), msgAndArgs...)
    }

    return true
}

// ErrorContains asserts that a function returned an error (i.e. not `nil`)
// and that the error contains the specified substring.
func ErrorContains(t TestingT, theError error, contains string, msgAndArgs ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    if !Error(t, theError, msgAndArgs...) {
        return false
    }

    actual := theError.Error()
    if !strings.Contains(actual, contains) {
        return Fail(t, fmt.Sprintf("Error %#v does not contain %#v", actual, contains), msgAndArgs...)
    }

    return true
}

// ErrorIs asserts that at least one of the errors in err's chain matches target.
// This is a wrapper for errors.Is.
func ErrorIs(t TestingT, err, target error, msgAndArgs ...interface{}) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    if errors.Is(err, target) {
        return true
    }

    var expectedText string
    if target != nil {
        expectedText = target.Error()
    }

    chain := buildErrorChainString(err)

    return Fail(t, fmt.Sprintf("Target error should be in err chain:\n"+
        "expected: %q\n"+
        "in chain: %s", expectedText, chain,
    ), msgAndArgs...)
}

// NotErrorIs asserts that none of the errors in err's chain matches target.
// This is a wrapper for errors.Is.
func NotErrorIs(t TestingT, err, target error, msgAndArgs ...interface{}) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    if !errors.Is(err, target) {
        return true
    }

    var expectedText string
    if target != nil {
        expectedText = target.Error()
    }

    chain := buildErrorChainString(err)

    return Fail(t, fmt.Sprintf("Target error should not be in err chain:\n"+
        "found: %q\n"+
        "in chain: %s", expectedText, chain,
    ), msgAndArgs...)
}

// ErrorAs asserts that at least one of the errors in err's chain matches target, and if so, sets target to that error value.
// This is a wrapper for errors.As.
func ErrorAs(t TestingT, err error, target interface{}, msgAndArgs ...interface{}) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    if errors.As(err, target) {
        return true
    }

    chain := buildErrorChainString(err)

    return Fail(t, fmt.Sprintf("Should be in error chain:\n"+
        "expected: %q\n"+
        "in chain: %s", target, chain,
    ), msgAndArgs...)
}

// NotErrorAs asserts that none of the errors in err's chain matches target,
// but if so, sets target to that error value.
func NotErrorAs(t TestingT, err error, target interface{}, msgAndArgs ...interface{}) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }
    if !errors.As(err, target) {
        return true
    }

    chain := buildErrorChainString(err)

    return Fail(t, fmt.Sprintf("Target error should not be in err chain:\n"+
        "found: %q\n"+
        "in chain: %s", target, chain,
    ), msgAndArgs...)
}

// Zero asserts that i is the zero value for its type.
func Zero(t TestingT, i any, msgAndArgs ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    if i != nil && !reflect.DeepEqual(i, reflect.Zero(reflect.TypeOf(i)).Interface()) {
        return Fail(t, fmt.Sprintf("Should be zero, but was %v", i), msgAndArgs...)
    }

    return true
}

// NotZero asserts that i is not the zero value for its type.
func NotZero(t TestingT, i any, msgAndArgs ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    if i == nil || reflect.DeepEqual(i, reflect.Zero(reflect.TypeOf(i)).Interface()) {
        return Fail(t, fmt.Sprintf("Should not be zero, but was %v", i), msgAndArgs...)
    }

    return true
}

// Condition uses a Comparison to assert a complex condition.
func Condition(t TestingT, comp Comparison, msgAndArgs ...interface{}) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    result := comp()
    if !result {
        Fail(t, "Condition failed!", msgAndArgs...)
    }

    return result
}

// WithinDuration asserts that the two times are within duration delta of each other.
//
//	test.WithinDuration(t, time.Now(), time.Now(), 10*time.Second)
func WithinDuration(t TestingT, expected, actual time.Time, delta time.Duration, msgAndArgs ...interface{}) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    dt := expected.Sub(actual)
    if dt < -delta || dt > delta {
        return Fail(t, fmt.Sprintf("Max difference between %v and %v allowed is %v, but difference was %v", expected, actual, delta, dt), msgAndArgs...)
    }

    return true
}

// WithinRange asserts that a time is within a time range (inclusive).
//
//	test.WithinRange(t, time.Now(), time.Now().Add(-time.Second), time.Now().Add(time.Second))
func WithinRange(t TestingT, actual, start, end time.Time, msgAndArgs ...interface{}) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    if end.Before(start) {
        return Fail(t, "Start should be before end", msgAndArgs...)
    }

    if actual.Before(start) {
        return Fail(t, fmt.Sprintf("Time %v expected to be in time range %v to %v, but is before the range", actual, start, end), msgAndArgs...)
    } else if actual.After(end) {
        return Fail(t, fmt.Sprintf("Time %v expected to be in time range %v to %v, but is after the range", actual, start, end), msgAndArgs...)
    }

    return true
}

// didPanic returns true if the function passed to it panics. Otherwise, it returns false.
func didPanic(f PanicTestFunc) (didPanic bool, message any, stack string) {
    didPanic = true

    defer func() {
        message = recover()
        if didPanic {
            stack = string(debug.Stack())
        }
    }()

    // call the target function
    f()
    didPanic = false

    return
}

// Panics asserts that the code inside the specified PanicTestFunc panics.
//
//	test.Panics(t, func(){ GoCrazy() })
func Panics(t TestingT, f PanicTestFunc, msgAndArgs ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    if funcDidPanic, panicValue, _ := didPanic(f); !funcDidPanic {
        return Fail(t, fmt.Sprintf("func %#v should panic\n\tPanic value:\t%#v", f, panicValue), msgAndArgs...)
    }

    return true
}

// PanicsWithValue asserts that the code inside the specified PanicTestFunc panics, and that
// the recovered panic value equals the expected panic value.
//
//	test.PanicsWithValue(t, "crazy error", func(){ GoCrazy() })
func PanicsWithValue(t TestingT, expected any, f PanicTestFunc, msgAndArgs ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    funcDidPanic, panicValue, panickedStack := didPanic(f)
    if !funcDidPanic {
        return Fail(t, fmt.Sprintf("func %#v should panic\n\tPanic value:\t%#v", f, panicValue), msgAndArgs...)
    }

    if panicValue != expected {
        return Fail(t, fmt.Sprintf("func %#v should panic with value:\t%#v\n\tPanic value:\t%#v\n\tPanic stack:\t%s", f, expected, panicValue, panickedStack), msgAndArgs...)
    }

    return true
}

// PanicsWithError asserts that the code inside the specified PanicTestFunc
// panics, and that the recovered panic value is an error that satisfies the
// EqualError comparison.
//
//	test.PanicsWithError(t, "crazy error", func(){ GoCrazy() })
func PanicsWithError(t TestingT, errString string, f PanicTestFunc, msgAndArgs ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    funcDidPanic, panicValue, panickedStack := didPanic(f)
    if !funcDidPanic {
        return Fail(t, fmt.Sprintf("func %#v should panic\n\tPanic value:\t%#v", f, panicValue), msgAndArgs...)
    }

    panicErr, ok := panicValue.(error)
    if !ok || panicErr.Error() != errString {
        return Fail(t, fmt.Sprintf("func %#v should panic with error message:\t%#v\n\tPanic value:\t%#v\n\tPanic stack:\t%s", f, errString, panicValue, panickedStack), msgAndArgs...)
    }

    return true
}

// NotPanics asserts that the code inside the specified PanicTestFunc does NOT panic.
//
//	test.NotPanics(t, func(){ RemainCalm() })
func NotPanics(t TestingT, f PanicTestFunc, msgAndArgs ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    if funcDidPanic, panicValue, panickedStack := didPanic(f); funcDidPanic {
        return Fail(t, fmt.Sprintf("func %#v should not panic\n\tPanic value:\t%v\n\tPanic stack:\t%s", f, panicValue, panickedStack), msgAndArgs...)
    }

    return true
}

// FailNow fails test
func FailNow(t TestingT, failureMessage string, msgAndArgs ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    Fail(t, failureMessage, msgAndArgs...)

    if t, ok := t.(failNower); ok {
        t.FailNow()
    } else {
        panic("test failed and t is missing `FailNow()`")
    }

    return false
}

// Fail reports a failure through
func Fail(t TestingT, failureMessage string, msgAndArgs ...any) bool {
    if h, ok := t.(tHelper); ok {
        h.Helper()
    }

    content := []labeledContent{
        {"Error Trace", strings.Join(CallerInfo(), "\n\t\t\t")},
        {"Error", failureMessage},
    }

    // Add test name if the Go version supports it
    if n, ok := t.(interface {
        Name() string
    }); ok {
        content = append(content, labeledContent{"Test", n.Name()})
    }

    message := messageFromMsgAndArgs(msgAndArgs...)
    if len(message) > 0 {
        content = append(content, labeledContent{"Messages", message})
    }

    t.Errorf("\n%s", "" + labeledOutput(content...))

    return false
}

// CallerInfo returns an array of strings containing the file and line number
// of each stack frame leading from the current test to the assert call that
// failed.
func CallerInfo() []string {
    var pc uintptr
    var ok bool
    var file string
    var line int
    var name string

    callers := []string{}
    for i := 0; ; i++ {
        pc, file, line, ok = runtime.Caller(i)
        if !ok {
            // The breaks below failed to terminate the loop, and we ran off the
            // end of the call stack.
            break
        }

        // This is a huge edge case, but it will panic if this is the case, see #180
        if file == "<autogenerated>" {
            break
        }

        f := runtime.FuncForPC(pc)
        if f == nil {
            break
        }
        name = f.Name()

        // testing.tRunner is the standard library function that calls
        // tests. Subtests are called directly by tRunner, without going through
        // the Test/Benchmark/Example function that contains the t.Run calls, so
        // with subtests we should break when we hit tRunner, without adding it
        // to the list of callers.
        if name == "testing.tRunner" {
            break
        }

        parts := strings.Split(file, "/")
        if len(parts) > 1 {
            filename := parts[len(parts)-1]
            dir := parts[len(parts)-2]
            if (dir != "assert" && dir != "mock" && dir != "require") || filename == "mock_test.go" {
                callers = append(callers, fmt.Sprintf("%s:%d", file, line))
            }
        }

        // Drop the package
        segments := strings.Split(name, ".")
        name = segments[len(segments)-1]
        if isTest(name, "Test") ||
            isTest(name, "Benchmark") ||
            isTest(name, "Example") {
            break
        }
    }

    return callers
}

type labeledContent struct {
    label   string
    content string
}

// validateEqualArgs checks whether provided arguments can be safely used in the
// Equal/NotEqual functions.
func validateEqualArgs(expected, actual any) error {
    if expected == nil && actual == nil {
        return nil
    }

    if isFunction(expected) || isFunction(actual) {
        return errors.New("cannot take func type as argument")
    }

    return nil
}

func isFunction(arg any) bool {
    if arg == nil {
        return false
    }

    return reflect.TypeOf(arg).Kind() == reflect.Func
}

func formatUnequalValues(expected, actual any) (e string, a string) {
    if reflect.TypeOf(expected) != reflect.TypeOf(actual) {
        return fmt.Sprintf("%T(%s)", expected, truncatingFormat(expected)),
            fmt.Sprintf("%T(%s)", actual, truncatingFormat(actual))
    }

    switch expected.(type) {
        case time.Duration:
            return fmt.Sprintf("%v", expected), fmt.Sprintf("%v", actual)
    }

    return truncatingFormat(expected), truncatingFormat(actual)
}

func truncatingFormat(data any) string {
    value := fmt.Sprintf("%#v", data)

    max := bufio.MaxScanTokenSize - 100 // Give us some space the type info too if needed.
    if len(value) > max {
        value = value[0:max] + "<... truncated>"
    }

    return value
}

func messageFromMsgAndArgs(msgAndArgs ...any) string {
    if len(msgAndArgs) == 0 || msgAndArgs == nil {
        return ""
    }

    if len(msgAndArgs) == 1 {
        msg := msgAndArgs[0]
        if msgAsStr, ok := msg.(string); ok {
            return msgAsStr
        }

        return fmt.Sprintf("%+v", msg)
    }

    if len(msgAndArgs) > 1 {
        return fmt.Sprintf(msgAndArgs[0].(string), msgAndArgs[1:]...)
    }

    return ""
}

func labeledOutput(content ...labeledContent) string {
    longestLabel := 0
    for _, v := range content {
        if len(v.label) > longestLabel {
            longestLabel = len(v.label)
        }
    }

    var output string
    for _, v := range content {
        output += "\t" + v.label + ":" + strings.Repeat(" ", longestLabel-len(v.label)) + "\t" + indentMessageLines(v.content, longestLabel) + "\n"
    }

    return output
}

func samePointers(first, second any) (same bool, ok bool) {
    firstPtr, secondPtr := reflect.ValueOf(first), reflect.ValueOf(second)
    if firstPtr.Kind() != reflect.Ptr || secondPtr.Kind() != reflect.Ptr {
        return false, false
    }

    firstType, secondType := reflect.TypeOf(first), reflect.TypeOf(second)
    if firstType != secondType {
        return false, true
    }

    return first == second, true
}

// copyExportedFields iterates downward through nested data structures and creates a copy
// that only contains the exported struct fields.
func copyExportedFields(expected any) any {
    if isNil(expected) {
        return expected
    }

    expectedType := reflect.TypeOf(expected)
    expectedKind := expectedType.Kind()
    expectedValue := reflect.ValueOf(expected)

    switch expectedKind {
        case reflect.Struct:
            result := reflect.New(expectedType).Elem()
            for i := 0; i < expectedType.NumField(); i++ {
                field := expectedType.Field(i)
                isExported := field.IsExported()
                if isExported {
                    fieldValue := expectedValue.Field(i)
                    if isNil(fieldValue) || isNil(fieldValue.Interface()) {
                        continue
                    }

                    newValue := copyExportedFields(fieldValue.Interface())
                    result.Field(i).Set(reflect.ValueOf(newValue))
                }
            }

            return result.Interface()

        case reflect.Ptr:
            result := reflect.New(expectedType.Elem())
            unexportedRemoved := copyExportedFields(expectedValue.Elem().Interface())
            result.Elem().Set(reflect.ValueOf(unexportedRemoved))
            return result.Interface()

        case reflect.Array, reflect.Slice:
            var result reflect.Value
            if expectedKind == reflect.Array {
                result = reflect.New(reflect.ArrayOf(expectedValue.Len(), expectedType.Elem())).Elem()
            } else {
                result = reflect.MakeSlice(expectedType, expectedValue.Len(), expectedValue.Len())
            }

            for i := 0; i < expectedValue.Len(); i++ {
                index := expectedValue.Index(i)
                if isNil(index) {
                    continue
                }

                unexportedRemoved := copyExportedFields(index.Interface())
                result.Index(i).Set(reflect.ValueOf(unexportedRemoved))
            }

            return result.Interface()

        case reflect.Map:
            result := reflect.MakeMap(expectedType)
            for _, k := range expectedValue.MapKeys() {
                index := expectedValue.MapIndex(k)
                unexportedRemoved := copyExportedFields(index.Interface())
                result.SetMapIndex(k, reflect.ValueOf(unexportedRemoved))
            }
            return result.Interface()

        default:
            return expected
    }
}

// isNil checks if a specified object is nil or not, without Failing.
func isNil(object any) bool {
    if object == nil {
        return true
    }

    value := reflect.ValueOf(object)
    switch value.Kind() {
        case
            reflect.Chan, reflect.Func,
            reflect.Interface, reflect.Map,
            reflect.Ptr, reflect.Slice, reflect.UnsafePointer:

            return value.IsNil()
    }

    return false
}

// isEmpty gets whether the specified object is considered empty or not.
func isEmpty(object any) bool {
    // get nil case out of the way
    if object == nil {
        return true
    }

    objValue := reflect.ValueOf(object)

    switch objValue.Kind() {
        // collection types are empty when they have no element
        case reflect.Chan,
            reflect.Map,
            reflect.Slice:
            return objValue.Len() == 0
        // pointers are empty if nil or if the value they point to is empty
        case reflect.Ptr:
            if objValue.IsNil() {
                return true
            }

            deref := objValue.Elem().Interface()
            return isEmpty(deref)
        // for all other types, compare against the zero value
        // array types are empty when they match their zero-initialized state
        default:
            zero := reflect.Zero(objValue.Type())
            return reflect.DeepEqual(object, zero.Interface())
    }
}

// isNumericType returns true if the type is one of:
// int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64,
// float32, float64, complex64, complex128
func isNumericType(t reflect.Type) bool {
    return t.Kind() >= reflect.Int && t.Kind() <= reflect.Complex128
}

func isTest(name, prefix string) bool {
    if !strings.HasPrefix(name, prefix) {
        return false
    }

    if len(name) == len(prefix) { // "Test" is ok
        return true
    }

    r, _ := utf8.DecodeRuneInString(name[len(prefix):])
    return !unicode.IsLower(r)
}

// Aligns the provided message so that all lines after the first line start at the same location as the first line.
func indentMessageLines(message string, longestLabelLen int) string {
    outBuf := new(bytes.Buffer)

    for i, scanner := 0, bufio.NewScanner(strings.NewReader(message)); scanner.Scan(); i++ {
        if i != 0 {
            outBuf.WriteString("\n\t" + strings.Repeat(" ", longestLabelLen+1) + "\t")
        }

        outBuf.WriteString(scanner.Text())
    }

    return outBuf.String()
}

func buildErrorChainString(err error) string {
    if err == nil {
        return ""
    }

    e := errors.Unwrap(err)
    chain := fmt.Sprintf("%q", err.Error())
    for e != nil {
        chain += fmt.Sprintf("\n\t%q", e.Error())
        e = errors.Unwrap(e)
    }

    return chain
}
