package interfaces

// 管道接口
type Pipeline interface {
    // 传递的数据
    Send(any) Pipeline

    // 传递的步骤
    Through(...any) Pipeline

    // 最后的结果
    Then(func(any) any) any
}
