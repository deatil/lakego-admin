package event

var e *Events

func init() {
    e = NewEvents()
}

// 监听
func Listen(name any, handler any) {
    e.Listen(name, handler)
}

// 注册事件订阅者
func Subscribe(subscribers ...any) {
    e.Subscribe(subscribers...)
}

// 注册事件观察者
func Observe(observer any, prefix string) {
    e.Observe(observer, prefix)
}

// 事件调度
func Dispatch(name any, object ...any) bool {
    return e.Dispatch(name, object...)
}

// 移除
func RemoveEvent(name any) bool {
    return e.RemoveEvent(name)
}

// 判断存在
func HasEvent(name any) bool {
    return e.HasEvent(name)
}

// 移除
func RemoveListen(name any, handler any) bool {
    return e.RemoveListen(name, handler)
}

// 判断存在
func HasListen(name any, handler any) bool {
    return e.HasListen(name, handler)
}

// 事件列表
func EventNames() []string {
    return e.EventNames()
}

// 事件对应监听列表
func EventListeners(name any) []*EventListener {
    return e.EventListeners(name)
}

// 重置
func Reset() {
    e = NewEvents()
}
