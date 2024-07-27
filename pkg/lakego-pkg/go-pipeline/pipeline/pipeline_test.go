package pipeline

import (
    "fmt"
    "reflect"
    "testing"
)

func assertErrorT(t *testing.T) func(error, string) {
    return func(err error, msg string) {
        if err != nil {
            t.Errorf("Failed %s: error: %+v", msg, err)
        }
    }
}

func assertEqualT(t *testing.T) func(any, any, string) {
    return func(actual any, expected any, msg string) {
        if !reflect.DeepEqual(actual, expected) {
            t.Errorf("Failed %s: actual: %v, expected: %v", msg, actual, expected)
        }
    }
}

// ===========

// 管道测试
type PipelineEx struct {}

func (this PipelineEx) Handle(data any, next NextFunc) any {
    old := data.(string)

    old = old + ", struct 数据1"

    data2 := next(old)

    data2 = data2.(string) + ", struct 数据2"

    return data2
}

// 管道测试
type PipelineEx2 struct {}

func (this PipelineEx2) SomeData(data any, next NextFunc) any {
    old := data.(string)

    old = old + ", PipelineEx2 数据1"

    data2 := next(old)

    data2 = data2.(string) + ", PipelineEx2 数据2"

    return data2
}

// 管道测试
type PipelineExFail struct {}

func (this PipelineExFail) Handle(data any, next NextFunc, instr string) any {
    old := data.(string)

    old = old + ", struct 数据1"

    data2 := next(old)

    data2 = data2.(string) + ", struct 数据2"

    return data2
}

func Test_Pipeline_1(t *testing.T) {
    eq := assertEqualT(t)

    // 管道测试
    data := New().
        Send("开始的数据").
        Through(
            func(data any, next NextFunc) any {
                old := data.(string)
                old = old + ", 第1次数据1"

                res := next(old)
                res = res.(string) + ", 第1次数据2"

                return res
            },
            func(data any, next NextFunc) any {
                old := data.(string)
                old = old + ", 第2次数据1"

                res := next(old)
                res = res.(string) + ", 第2次数据2"

                return res
            },
            &PipelineEx{},
        ).
        ThenReturn()

    check := "开始的数据, 第1次数据1, 第2次数据1, struct 数据1, struct 数据2, 第2次数据2, 第1次数据2"
    eq(data, check, "failed pipeline")
}

func Test_Pipeline_2(t *testing.T) {
    eq := assertEqualT(t)

    // 管道测试
    data := New().
        Send("开始的数据2").
        Via("SomeData").
        Through(
            func(data any, next NextFunc) any {
                old := data.(string)
                old = old + ", 第1次数据1"

                res := next(old)
                res = res.(string) + ", 第1次数据2"

                return res
            },
            func(data any, next NextFunc) any {
                old := data.(string)
                old = old + ", 第2次数据1"

                res := next(old)
                res = res.(string) + ", 第2次数据2"

                return res
            },
            &PipelineEx2{},
        ).
        ThenReturn()

    check := "开始的数据2, 第1次数据1, 第2次数据1, PipelineEx2 数据1, PipelineEx2 数据2, 第2次数据2, 第1次数据2"
    eq(data, check, "failed pipeline 2")
}

func Test_Pipeline_3(t *testing.T) {
    eq := assertEqualT(t)

    // 管道测试
    data := New().
        Send("开始的数据2").
        Via("SomeData").
        Pipe(
            func(data any, next NextFunc) any {
                old := data.(string)
                old = old + ", 第1次数据1"

                res := next(old)
                res = res.(string) + ", 第1次数据2"

                return res
            },
            func(data any, next NextFunc) any {
                old := data.(string)
                old = old + ", 第2次数据1"

                res := next(old)
                res = res.(string) + ", 第2次数据2"

                return res
            },
        ).
        Pipe(
            &PipelineEx2{},
        ).
        ThenReturn()

    check := "开始的数据2, 第1次数据1, 第2次数据1, PipelineEx2 数据1, PipelineEx2 数据2, 第2次数据2, 第1次数据2"
    eq(data, check, "failed pipeline 3")
}

func Test_Pipeline_33(t *testing.T) {
    eq := assertEqualT(t)

    // 管道测试
    data := New().
        Send("开始的数据2").
        Via("SomeData").
        PipeArray(
            []PipeItem{
                func(data any, next NextFunc) any {
                    old := data.(string)
                    old = old + ", 第1次数据1"

                    res := next(old)
                    res = res.(string) + ", 第1次数据2"

                    return res
                },
                func(data any, next NextFunc) any {
                    old := data.(string)
                    old = old + ", 第2次数据1"

                    res := next(old)
                    res = res.(string) + ", 第2次数据2"

                    return res
                },
            },
        ).
        Pipe(
            &PipelineEx2{},
        ).
        ThenReturn()

    check := "开始的数据2, 第1次数据1, 第2次数据1, PipelineEx2 数据1, PipelineEx2 数据2, 第2次数据2, 第1次数据2"
    eq(data, check, "failed pipeline 33")
}

func Test_Pipeline_5(t *testing.T) {
    eq := assertEqualT(t)

    // 管道测试
    data := New().
        Send("开始的数据2").
        Via("SomeData").
        ThroughArray(
            []PipeItem{
                func(data any, next NextFunc) any {
                    old := data.(string)
                    old = old + ", 第1次数据1"

                    res := next(old)
                    res = res.(string) + ", 第1次数据2"

                    return res
                },
                func(data any, next NextFunc) any {
                    old := data.(string)
                    old = old + ", 第2次数据1"

                    res := next(old)
                    res = res.(string) + ", 第2次数据2"

                    return res
                },
                &PipelineEx2{},
            },
        ).
        ThenReturn()

    check := "开始的数据2, 第1次数据1, 第2次数据1, PipelineEx2 数据1, PipelineEx2 数据2, 第2次数据2, 第1次数据2"
    eq(data, check, "failed pipeline 5")
}

func Test_Pipeline_6(t *testing.T) {
    eq := assertEqualT(t)

    var1 := "var1-data"

    // 管道测试
    data := New().
        Send("开始的数据").
        Through(
            // 传递额外数据
            []any{
                func(data any, next NextFunc, invar1 string) any {
                    old := data.(string)
                    old = old + ", 第1次数据1"

                    res := next(old)
                    res = res.(string) + ", 第1次数据2, var: " + invar1 + ", "

                    return res
                },
                var1,
            },
            func(data any, next NextFunc) any {
                old := data.(string)
                old = old + ", 第2次数据1"

                res := next(old)
                res = res.(string) + ", 第2次数据2"

                return res
            },
            &PipelineEx{},
        ).
        ThenReturn()

    check := "开始的数据, 第1次数据1, 第2次数据1, struct 数据1, struct 数据2, 第2次数据2, 第1次数据2, var: var1-data, "
    eq(data, check, "failed pipeline 6")
}

func Test_Pipeline_7(t *testing.T) {
    eq := assertEqualT(t)

    // 管道测试
    data := New().
        Send("开始的数据").
        Through(
            // 传递额外数据
            []any{
                func(data any, next NextFunc) any {
                    old := data.(string)
                    old = old + ", 第1次数据1"

                    res := next(old)
                    res = res.(string) + ", 第1次数据2"

                    return res
                },
            },
            func(data any, next NextFunc) any {
                old := data.(string)
                old = old + ", 第2次数据1"

                res := next(old)
                res = res.(string) + ", 第2次数据2"

                return res
            },
            &PipelineEx{},
        ).
        ThenReturn()

    check := "开始的数据, 第1次数据1, 第2次数据1, struct 数据1, struct 数据2, 第2次数据2, 第1次数据2"
    eq(data, check, "failed pipeline 7")
}

func Test_Pipeline_fail_1(t *testing.T) {
    eq := assertEqualT(t)

    // 管道测试
    data := New().
        Send("开始的数据").
        Through(
            func(data any, next NextFunc) any {
                old := data.(string)
                old = old + ", 第1次数据1"

                res := next(old)
                res = res.(string) + ", 第1次数据2"

                return res
            },
            func(data any, next NextFunc) {
                old := data.(string)
                old = old + ", 第2次数据1"

                res := next(old)
                res = res.(string) + ", 第2次数据2"

                return
            },
            &PipelineEx{},
        ).
        ThenReturn()

    check := "开始的数据, 第1次数据1, struct 数据1, struct 数据2, 第1次数据2"
    eq(data, check, "failed pipeline fail 1")
}

func Test_Pipeline_fail_2(t *testing.T) {
    eq := assertEqualT(t)

    var1 := "var1-data"

    // 管道测试
    data := New().
        Send("开始的数据").
        Through(
            // 传递额外数据
            []any{
                func(data any, next NextFunc, invar1 string) {
                    old := data.(string)
                    old = old + ", 第1次数据1"

                    res := next(old)
                    res = res.(string) + ", 第1次数据2, var: " + invar1 + ", "

                    return
                },
                var1,
            },
            func(data any, next NextFunc) any {
                old := data.(string)
                old = old + ", 第2次数据1"

                res := next(old)
                res = res.(string) + ", 第2次数据2"

                return res
            },
            &PipelineEx{},
        ).
        ThenReturn()

    check := "开始的数据, 第2次数据1, struct 数据1, struct 数据2, 第2次数据2"
    eq(data, check, "failed pipeline fail 2")
}

func Test_Pipeline_fail_3(t *testing.T) {
    eq := assertEqualT(t)

    defer func() {
        if e := recover(); e != nil {
            err := fmt.Sprintf("%v", e)

            check := "go-pipeline: func params error (args 2, func args 3)"
            eq(err, check, "failed pipeline fail 3")
        }
    }()

    // 管道测试
    _ = New().
        Send("开始的数据").
        Through(
            // 传递额外数据
            []any{
                func(data any, next NextFunc, instr string) any {
                    old := data.(string)
                    old = old + ", 第1次数据1"

                    res := next(old)
                    res = res.(string) + ", 第1次数据2"

                    return res
                },
            },
            func(data any, next NextFunc) any {
                old := data.(string)
                old = old + ", 第2次数据1"

                res := next(old)
                res = res.(string) + ", 第2次数据2"

                return res
            },
            &PipelineEx{},
        ).
        ThenReturn()
}

func Test_Pipeline_fail_33(t *testing.T) {
    eq := assertEqualT(t)

    defer func() {
        if e := recover(); e != nil {
            err := fmt.Sprintf("%v", e)

            check := "go-pipeline: func params error (args 2, func args 3)"
            eq(err, check, "failed pipeline fail 33")
        }
    }()

    // 管道测试
    _ = New().
        Send("开始的数据").
        Through(
            // 传递额外数据
            []any{
                func(data any, next NextFunc) any {
                    old := data.(string)
                    old = old + ", 第1次数据1"

                    res := next(old)
                    res = res.(string) + ", 第1次数据2"

                    return res
                },
            },
            func(data any, next NextFunc, instr string) any {
                old := data.(string)
                old = old + ", 第2次数据1"

                res := next(old)
                res = res.(string) + ", 第2次数据2"

                return res
            },
            &PipelineEx{},
        ).
        ThenReturn()
}

func Test_Pipeline_fail_5(t *testing.T) {
    eq := assertEqualT(t)

    defer func() {
        if e := recover(); e != nil {
            err := fmt.Sprintf("%v", e)

            check := "go-pipeline: func params error (args 2, func args 3)"
            eq(err, check, "failed pipeline fail 5")
        }
    }()

    // 管道测试
    _ = New().
        Send("开始的数据").
        Through(
            // 传递额外数据
            []any{
                func(data any, next NextFunc) any {
                    old := data.(string)
                    old = old + ", 第1次数据1"

                    res := next(old)
                    res = res.(string) + ", 第1次数据2"

                    return res
                },
            },
            func(data any, next NextFunc) any {
                old := data.(string)
                old = old + ", 第2次数据1"

                res := next(old)
                res = res.(string) + ", 第2次数据2"

                return res
            },
            &PipelineExFail{},
        ).
        ThenReturn()
}

func Test_Pipeline_fail_6(t *testing.T) {
    eq := assertEqualT(t)

    // 管道测试
    data := New().
        Send("开始的数据").
        Through(
            func(data any, next NextFunc) any {
                old := data.(string)
                old = old + ", 第1次数据1"

                res := next(old)
                res = res.(string) + ", 第1次数据2"

                return res
            },
            func(data any, next NextFunc) any {
                old := data.(string)
                old = old + ", 第2次数据1"

                res := next(old)
                res = res.(string) + ", 第2次数据2"

                return res
            },
            &PipelineEx{},
            "testestest",
        ).
        ThenReturn()

    check := "开始的数据, 第1次数据1, 第2次数据1, struct 数据1, struct 数据2, 第2次数据2, 第1次数据2"
    eq(data, check, "failed pipeline fail 6")
}

// ===========

func Test_Hub(t *testing.T) {
    eq := assertEqualT(t)

    hub := NewHub()
    hub.Pipeline("hub", func(pipe *Pipeline, object any) any {
        data := pipe.
            Send(object).
            Through(
                func(data any, next NextFunc) any {
                    old := data.(string)
                    old = old + ", 第1次数据1"

                    data2 := next(old)
                    data2 = data2.(string) + ", 第1次数据2"

                    return data2
                },
            ).
            ThenReturn()

        return data
    })
    data := hub.Pipe("hub 测试", "hub")

    check := "hub 测试, 第1次数据1, 第1次数据2"
    eq(data, check, "failed Hub")
}

func Test_Hub_2(t *testing.T) {
    eq := assertEqualT(t)

    hub := NewHub()
    hub.Defaults(func(pipe *Pipeline, object any) any {
        data := pipe.
            Send(object).
            Through(
                func(data any, next NextFunc) any {
                    old := data.(string)
                    old = old + ", 第1次数据1"

                    data2 := next(old)
                    data2 = data2.(string) + ", 第1次数据2"

                    return data2
                },
            ).
            ThenReturn()

        return data
    })
    data := hub.Pipe("hub 测试")

    check := "hub 测试, 第1次数据1, 第1次数据2"
    eq(data, check, "failed Hub 2")
}

func Test_Hub_3(t *testing.T) {
    eq := assertEqualT(t)

    DefaultHub.Pipeline("hub", func(pipe *Pipeline, object any) any {
        data := pipe.
            Send(object).
            Through(
                func(data any, next NextFunc) any {
                    old := data.(string)
                    old = old + ", 第1次数据1"

                    data2 := next(old)
                    data2 = data2.(string) + ", 第1次数据2"

                    return data2
                },
            ).
            ThenReturn()

        return data
    })
    DefaultHub.Pipeline("hub2", func(pipe *Pipeline, object any) any {
        data := pipe.
            Send(object).
            Through(
                func(data any, next NextFunc) any {
                    old := data.(string)
                    old = old + ", 第11次数据1"

                    data2 := next(old)
                    data2 = data2.(string) + ", 第11次数据2"

                    return data2
                },
            ).
            ThenReturn()

        return data
    })
    data := DefaultHub.Pipe("hub 测试", "hub")
    data2 := DefaultHub.Pipe("hub 测试2", "hub2")

    check := "hub 测试, 第1次数据1, 第1次数据2"
    eq(data, check, "failed Hub")

    check2 := "hub 测试2, 第11次数据1, 第11次数据2"
    eq(data2, check2, "failed Hub")
}

// ===========

// 管道测试
type PipelineExType struct {}

func (this PipelineExType) Handle(data string, next NextFunc) string {
    old := data + ", struct 数据1"

    data2 := next(old)

    res2 := data2.(string) + ", struct 数据2"

    return res2
}

func Test_Pipeline_12(t *testing.T) {
    eq := assertEqualT(t)

    // 管道测试
    data := New().
        Send("开始的数据").
        Through(
            func(data string, next NextFunc) string {
                old := data + ", 第1次数据1"

                res := next(old)

                res2 := res.(string) + ", 第1次数据2"

                return res2
            },
            func(data string, next NextFunc) string {
                old := data + ", 第2次数据1"

                res := next(old)

                res2 := res.(string) + ", 第2次数据2"

                return res2
            },
        ).
        ThenReturn()

    check := "开始的数据, 第1次数据1, 第2次数据1, 第2次数据2, 第1次数据2"
    eq(data, check, "failed pipeline")
}

func Test_Pipeline_StructType(t *testing.T) {
    eq := assertEqualT(t)

    // 管道测试
    data := New().
        Send("开始的数据").
        Through(
            func(data string, next NextFunc) string {
                old := data + ", 第1次数据1"

                res := next(old)

                res2 := res.(string) + ", 第1次数据2"

                return res2
            },
            func(data string, next NextFunc) string {
                old := data + ", 第2次数据1"

                res := next(old)

                res2 := res.(string) + ", 第2次数据2"

                return res2
            },
            &PipelineExType{},
        ).
        ThenReturn()

    check := "开始的数据, 第1次数据1, 第2次数据1, struct 数据1, struct 数据2, 第2次数据2, 第1次数据2"
    eq(data, check, "failed pipeline")
}
