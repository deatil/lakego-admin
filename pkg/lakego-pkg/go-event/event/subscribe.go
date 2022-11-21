package event

import(
    "reflect"
)

// 接口
type ISubscribe interface {
    Subscribe(*Events)
}

// 接口
type ISubscribePrefix interface {
    EventPrefix() string
}

// 订阅数据
type EventSubscribe struct {
    // 结构体
    Struct reflect.Value

    // 方法
    Method reflect.Method
}
