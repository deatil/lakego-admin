package pipeline

import (
    "sync"
)

var instanceHub *Hub
var once sync.Once

// 构造函数
func NewHub() *Hub {
    return &Hub{
        Pipelines: make(PipelinesMap),
    }
}

// 单例
func NewHubWithInstance() *Hub {
    once.Do(func() {
        instanceHub = NewHub()
    })

    return instanceHub
}

type (
    // 回调函数
    HubCallbackFunc = func(*Pipeline, interface{}) interface{}

    // 数据列表
    PipelinesMap = map[string]HubCallbackFunc
)

/**
 * Hub
 *
 * @create 2022-2-8
 * @author deatil
 */
type Hub struct {
    // 设置的数据
    Pipelines PipelinesMap
}

// 默认
func (this *Hub) Defaults(callback HubCallbackFunc) *Hub {
    return this.Pipeline("default", callback)
}

// 设置
func (this *Hub) Pipeline(name string, callback HubCallbackFunc) *Hub {
    this.Pipelines[name] = callback

    return this
}

// 执行
func (this *Hub) Pipe(object interface{}, pipeline ...string) interface{} {
    name := "default"

    if len(pipeline) > 0 {
        name = pipeline[0]
    }

    if pipelineCallback, ok := this.Pipelines[name]; ok {
        return pipelineCallback(NewPipeline(), object)
    }

    return nil
}
