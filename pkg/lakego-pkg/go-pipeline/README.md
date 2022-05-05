## 通用管道


### 项目介绍

*  go 实现的通用管道


### 下载安装

~~~go
go get -u github.com/deatil/go-pipeline
~~~


### 使用

~~~go
package main

import (
    "github.com/deatil/go-pipeline/pipeline"
)

func main() {
    // 管道测试
    data2 := pipeline.NewPipeline().
        Send("开始的数据").
        Through(
            func(data any, next pipeline.NextFunc) any {
                old := data.(string)
                old = old + ", 第1次数据1"

                data2 := next(old)
                data2 = data2.(string) + ", 第1次数据2"

                return data2
            },
            func(data any, next pipeline.NextFunc) any {
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
    hub.Pipeline("hub", func(pipe *pipeline.Pipeline, object any) any {
        data := pipe.
            Send(object).
            Through(
                func(data any, next pipeline.NextFunc) any {
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

func (this PipelineEx) Handle(data any, next pipeline.NextFunc) any {
    old := data.(string)

    old = old + ", struct 数据1"

    data2 := next(old)

    data2 = data2.(string) + ", struct 数据2"

    return data2
}

~~~


### 开源协议

*  本软件包遵循 `Apache2` 开源协议发布，在保留本软件包版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包所属版权归 deatil(https://github.com/deatil) 所有。
