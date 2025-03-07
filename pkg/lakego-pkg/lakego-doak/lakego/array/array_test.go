package array

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

func Test_newKey(t *testing.T) {
    eq := AssertEqualT(t)

    test := map[string]any{
        "test1": "value1",
        "test5": "value5",
        "test3": map[string]any{
            "string1": "111",
            "string2": 222,
            "string3": map[string]any{
                "test222": "val222",
            },
        },
    }

    eq(ArrayGet(test, "test3.string1").String(), "111", "ArrayGet")
    eq(ArrayGet(test, "test3.string22").String(), "", "ArrayGet nil")

    eq(ArrayHas(test, "test3.string1"), true, "ArrayHas")
    eq(ArrayHas(test, "test3.string23"), false, "ArrayHas false")

    {
        td := newKey(test)

        eq(td.Value("test3.string1").String(), "111", "newKey.Value")
        eq(td.Value("test3.string22").String(), "", "newKey.Value nil")
        eq(td.Has("test3.string1"), true, "newKey.Has")
        eq(td.Has("test3.string23"), false, "newKey.Has false")
        eq(td.ToJSON(), `{"test1":"value1","test3":{"string1":"111","string2":222,"string3":{"test222":"val222"}},"test5":"value5"}`, "newKey.ToJSON")
        eq(td.All().ToJSON(), `{"test1":"value1","test3":{"string1":"111","string2":222,"string3":{"test222":"val222"}},"test5":"value5"}`, "newKey.All().ToJSON")
    }

    {
        td := ArrayFrom(test)

        eq(td.Value("test3.string1").String(), "111", "newKey.Value")
        eq(td.Value("test3.string22").String(), "", "newKey.Value nil")
        eq(td.Has("test3.string1"), true, "newKey.Has")
        eq(td.Has("test3.string23"), false, "newKey.Has false")
        eq(td.ToJSON(), `{"test1":"value1","test3":{"string1":"111","string2":222,"string3":{"test222":"val222"}},"test5":"value5"}`, "newKey.ToJSON")
        eq(td.All().ToJSON(), `{"test1":"value1","test3":{"string1":"111","string2":222,"string3":{"test222":"val222"}},"test5":"value5"}`, "newKey.All().ToJSON")
    }
}

func Test_Diff(t *testing.T) {
    eq := AssertEqualT(t)

    {
        args1 := []string{"test1", "test"}
        args2 := []string{"test1", "Test"}

        diff := ArrayDiff(args1, args2)
        eq([]string{"Test"}, diff, "Diff string")

        diff2 := ArrayDiff(args2, args1)
        eq([]string{"test"}, diff2, "Diff string 2")
    }

    {
        args1 := []int{1, 2, 3}
        args2 := []int{0, 1, 2, 3, 5}

        diff := ArrayDiff(args1, args2)
        eq([]int{0, 5}, diff, "Diff int")
    }

    {
        args1 := []float64{1.1, 2, 3}
        args2 := []float64{1.0, 2, 2.5, 3, 5.6}

        diff := ArrayDiff(args1, args2)
        eq([]float64{1.0, 2.5, 5.6}, diff, "Diff float64")
    }

}
