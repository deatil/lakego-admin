package container

import (
    "reflect"
    "testing"
)

func assertDeepEqualT(t *testing.T) func(any, any, string) {
    return func(actual any, expected any, msg string) {
        if !reflect.DeepEqual(actual, expected) {
            t.Errorf("Failed %s: actual: %v, expected: %v", msg, actual, expected)
        }
    }
}

func Test_getFuncName(t *testing.T) {
    eq := assertDeepEqualT(t)

    newData := getFuncName(Test_getFuncName)

    eq(newData, "github.com/deatil/go-container/container.Test_getFuncName", "Test_getFuncName")
}

func Test_ConvertToTypes(t *testing.T) {
    eq := assertDeepEqualT(t)

    data := []any{
        "test aaa",
        "test bbb",
        "test ccc",
    }

    checkData := make([]reflect.Type, 0)
    for _, arg := range data {
        checkData = append(checkData, reflect.TypeOf(arg))
    }

    newData := ConvertToTypes(data...)

    eq(newData, checkData, "ConvertToTypes")
}
