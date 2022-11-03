package event

import(
    "sync"
)

var instance *EventDispatcher
var once sync.Once

// 单例模式
func NewDispatcher() *EventDispatcher {
    once.Do(func() {
        instance = NewEventDispatcher()
    })

    return instance
}

// 监听
func listen(name string, handler EventHandler) {
    listener := NewEventListener(handler)

    NewDispatcher().AddEventListener(name, listener)
}

// 监听
func Listen(name string, handler any) {
    switch fn := handler.(type) {
        // func(*Event)
        case EventHandler:
            listen(name, fn)

        case func(any):
            listen(name, func(e *Event) {
                fn(e.Object)
            })

        case func(any, string):
            listen(name, func(e *Event) {
                fn(e.Object, e.Type)
            })
    }
}

// 事件调度
func Dispatch(name string, object ...any) bool {
    var eventObject any
    if len(object) > 0 {
        eventObject = object[0]
    }

    cevent := NewEvent(name, eventObject)

    return NewDispatcher().DispatchEvent(cevent)
}

// 移除
func RemoveListen(name string, handler EventHandler) bool {
    listener := NewEventListener(handler)

    return NewDispatcher().RemoveEventListener(name, listener)
}

// 判断存在
func HasListen(name string) bool {
    return NewDispatcher().HasEventListener(name)
}
