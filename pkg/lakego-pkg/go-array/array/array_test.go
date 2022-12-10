package array

import (
    "fmt"
    "reflect"
    "testing"
    "encoding/json"
    "html/template"
)

var (
    arrData = map[string]any{
        "a": 123,
        "b": map[string]any{
            "c": "ccc",
            "d": map[string]any{
                "e": "eee",
                "f": map[string]any{
                    "g": "ggg",
                },
            },
            "dd": []any{
                "ccccc",
                "ddddd",
                "fffff",
            },
            "ff": map[any]any{
                111: "fccccc",
                222: "fddddd",
                333: "dfffff",
            },
            "hhTy3": &map[int]any{
                111: "hccccc",
                222: "hddddd",
                333: map[any]string{
                    "qq1": "qq1ccccc",
                    "qq2": "qq2ddddd",
                    "qq3": "qq3fffff",
                },
                666: []float64{
                    12.3,
                    32.5,
                    22.56,
                    789.156,
                },
            },
            "kJh21ay": map[string]any{
                "Hjk2": "fccDcc",
                "23rt": "^hgcF5c",
                "23rt5": []any{
                    "adfa",
                    1231,
                },
            },
        },
    }
)

func assertT(t *testing.T) func(any, string, string) {
    return func(actual any, expected string, msg string) {
        actualStr := toString(actual)
        if actualStr != expected {
            t.Errorf("Failed %s: actual: %v, expected: %v", msg, actualStr, expected)
        }
    }
}

func assertDeepEqualT(t *testing.T) func(any, any, string) {
    return func(actual any, expected any, msg string) {
        if !reflect.DeepEqual(actual, expected) {
            t.Errorf("Failed %s: actual: %v, expected: %v", msg, actual, expected)
        }
    }
}

func TestArray(t *testing.T) {
    assert := assertT(t)

    testData := []struct{
        key string
        expected string
        msg string
    }{
        {
            "a",
            "123",
            "map[string]any",
        },
        {
            "b.dd.1",
            "ddddd",
            "[]any",
        },
        {
            "b.ff.222",
            "fddddd",
            "map[any]any",
        },
        {
            "b.hhTy3.222",
            "hddddd",
            "&map[int]any",
        },
        {
            "b.hhTy3.333.qq2",
            "qq2ddddd",
            "map[any]string",
        },
        {
            "b.hhTy3.666.3",
            "789.156",
            "Slice",
        },
    }

    for _, v := range testData {
        assert(ArrGet(arrData, v.key), v.expected, v.msg)
    }

}

func TestToString(t *testing.T) {
    assert := assertDeepEqualT(t)

    var jn json.Number
    _ = json.Unmarshal([]byte("8"), &jn)
    type Key struct {
        k string
    }
    key := &Key{"foo"}

    tests := []struct {
        input  any
        expect string
    }{
        {int(8), "8"},
        {int8(8), "8"},
        {int16(8), "8"},
        {int32(8), "8"},
        {int64(8), "8"},
        {uint(8), "8"},
        {uint8(8), "8"},
        {uint16(8), "8"},
        {uint32(8), "8"},
        {uint64(8), "8"},
        {float32(8.31), "8.31"},
        {float64(8.31), "8.31"},
        {jn, "8"},
        {true, "true"},
        {false, "false"},
        {nil, ""},
        {[]byte("one time"), "one time"},
        {"one more time", "one more time"},
        {template.HTML("one time"), "one time"},
        {template.URL("http://somehost.foo"), "http://somehost.foo"},
        {template.JS("(1+2)"), "(1+2)"},
        {template.CSS("a"), "a"},
        {template.HTMLAttr("a"), "a"},
        // errors
        {testing.T{}, ""},
        {key, ""},
    }

    for i, test := range tests {
        errmsg := fmt.Sprintf("i = %d", i)

        v := toString(test.input)

        assert(v, test.expect, errmsg)
    }
}

func TestToStringMap(t *testing.T) {
    assert := assertDeepEqualT(t)

    tests := []struct {
        input  any
        expect map[string]any
    }{
        {map[any]any{"tag": "tags", "group": "groups"}, map[string]any{"tag": "tags", "group": "groups"}},
        {map[string]any{"tag": "tags", "group": "groups"}, map[string]any{"tag": "tags", "group": "groups"}},
        {`{"tag": "tags", "group": "groups"}`, map[string]any{"tag": "tags", "group": "groups"}},
        {`{"tag": "tags", "group": true}`, map[string]any{"tag": "tags", "group": true}},

        // errors
        {nil, nil},
        {testing.T{}, nil},
        {"", nil},
    }

    for i, test := range tests {
        errmsg := fmt.Sprintf("i = %d", i)

        v := toStringMap(test.input)

        assert(v, test.expect, errmsg)
    }
}

func Example() {
    ArrGet(arrData, "b.hhTy3.666.3")
}
