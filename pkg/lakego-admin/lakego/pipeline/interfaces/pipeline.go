package interfaces

// 管道接口
type Pipeline interface {
    // 传递的数据
    Send(interface{}) Pipeline

    // 传递的步骤
    Through(...interface{}) Pipeline

    // 最后的结果
    Then(func(interface{}) interface{}) interface{}
}
