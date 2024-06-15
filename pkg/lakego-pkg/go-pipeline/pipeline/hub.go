package pipeline

type (
    // 回调函数
    HubCallbackFunc = func(*Pipeline, any) any

    // 数据列表
    HubPipelinesMap = map[string]HubCallbackFunc
)

// 默认 hub
var DefaultHub = NewHub()

/**
 * Hub
 *
 * @create 2022-2-8
 * @author deatil
 */
type Hub struct {
    // 设置的数据
    Pipelines HubPipelinesMap
}

// 构造函数
func NewHub() *Hub {
    return &Hub{
        Pipelines: make(HubPipelinesMap),
    }
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
func (this *Hub) Pipe(object any, pipeline ...string) any {
    name := "default"

    if len(pipeline) > 0 {
        name = pipeline[0]
    }

    if pipelineCallback, ok := this.Pipelines[name]; ok {
        return pipelineCallback(NewPipeline(), object)
    }

    return nil
}
