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

func Test_getTypeName(t *testing.T) {
    eq := assertDeepEqualT(t)

    t1 := &testBind{}

    res := getStructName(t1)
    eq(res, "*github.com/deatil/go-container/container.testBind", "Test_getTypeName 1")

    t2 := &t1

    res = getStructName(t2)
    eq(res, "**github.com/deatil/go-container/container.testBind", "Test_getTypeName 1")

    t3 := &t2

    res = getStructName(t3)
    eq(res, "***github.com/deatil/go-container/container.testBind", "Test_getTypeName 1")
}
