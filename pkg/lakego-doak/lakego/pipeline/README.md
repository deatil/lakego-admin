## 通用管道


### 项目介绍

*  go 实现的通用管道


### 使用方法

~~~go
package main

import (
    "github.com/deatil/lakego-doak/lakego/pipeline"
)

func main() {
    // 管道测试
    data2 := pipeline.NewPipeline().
        Send("开始的数据").
        Through(
            func(data interface{}, next pipeline.NextFunc) interface{} {
                old := data.(string)
                old = old + ", 第1次数据1"

                data2 := next(old)
                data2 = data2.(string) + ", 第1次数据2"

                return data2
            },
            func(data interface{}, next pipeline.NextFunc) interface{} {
                old := data.(string)
                old = old + ", 第2次数据1"

                data2 := next(old)
                data2 = data2.(string) + ", 第2次数据2"

                return data2
            },
            &PipelineEx{},
        ).
        ThenReturn()

    // hub 测试
    hub := pipeline.NewHub()
    hub.Pipeline("hub", func(pipe *pipeline.Pipeline, object interface{}) interface{} {
        data := pipe.
            Send(object).
            Through(
                func(data interface{}, next pipeline.NextFunc) interface{} {
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
    data3 := hub.Pipe("hub 测试", "hub")
}

/* ======================== */

// 管道测试
type PipelineEx struct {}

func (this PipelineEx) Handle(data interface{}, next pipeline.NextFunc) interface{} {
    old := data.(string)

    old = old + ", struct 数据1"

    data2 := next(old)

    data2 = data2.(string) + ", struct 数据2"

    return data2
}

~~~