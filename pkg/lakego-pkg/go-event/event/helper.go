package event

var defaultEvents *Events

// 初始化
func init() {
    defaultEvents = NewEvents()
}

// 监听
func Listen(name any, handler any) {
    defaultEvents.Listen(name, handler)
}

// 注册事件订阅者
func Subscribe(subscribers ...any) {
    defaultEvents.Subscribe(subscribers...)
}

// 注册事件观察者
func Observe(observer any, prefix string) {
    defaultEvents.Observe(observer, prefix)
}

// 事件调度
func Dispatch(name any, object ...any) bool {
    return defaultEvents.Dispatch(name, object...)
}

// 移除
func RemoveEvent(name any) bool {
    return defaultEvents.RemoveEvent(name)
}

// 判断存在
func HasEvent(name any) bool {
    return defaultEvents.HasEvent(name)
}

// 移除
func RemoveListen(name any, handler any) bool {
    return defaultEvents.RemoveListen(name, handler)
}

// 判断存在
func HasListen(name any, handler any) bool {
    return defaultEvents.HasListen(name, handler)
}

// 事件列表
func EventNames() []string {
    return defaultEvents.EventNames()
}

// 事件对应监听列表
func EventListeners(name any) []*EventListener {
    return defaultEvents.EventListeners(name)
}

// 重置
func Reset() {
    defaultEvents = NewEvents()
}
