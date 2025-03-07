package utils

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

func Test_FormatAccess(t *testing.T) {
    eq := AssertEqualT(t)

    {
        args1 := []string{"test1", "test", "test2"}
        args2 := []string{"test1", "Test", "test2"}

        adds, deletes := FormatAccess(args1, args2)

        eq([]string{"Test"}, adds, "FormatAccess adds")
        eq([]string{"test"}, deletes, "FormatAccess deletes")
    }
}
