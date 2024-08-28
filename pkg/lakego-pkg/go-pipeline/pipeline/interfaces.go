package pipeline

// 管道接口
type IPipeline interface {
    // 传递的数据
    Send(any) *Pipeline

    // 传递的步骤
    Through(...any) *Pipeline

    // 最后的结果
    Then(func(any) any) any
}

// Hub 接口
type IHub interface {
    // Pipe
    Pipe(any, ...string) any
}
