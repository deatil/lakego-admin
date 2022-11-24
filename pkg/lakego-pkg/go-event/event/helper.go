package event

// 监听
func Listen(name any, handler any) {
    NewEvents().Listen(name, handler)
}

// 注册事件订阅者
func Subscribe(subscribers ...any) {
    NewEvents().Subscribe(subscribers...)
}

// 注册事件观察者
func Observe(observer any, prefix string) {
    NewEvents().Observe(observer, prefix)
}

// 事件调度
func Dispatch(name any, object ...any) bool {
    return NewEvents().Dispatch(name, object...)
}

// 移除
func RemoveEvent(name any) bool {
    return NewEvents().RemoveEvent(name)
}

// 判断存在
func HasEvent(name any) bool {
    return NewEvents().HasEvent(name)
}

// 移除
func RemoveListen(name any, handler any) bool {
    return NewEvents().RemoveListen(name, handler)
}

// 判断存在
func HasListen(name any, handler any) bool {
    return NewEvents().HasListen(name, handler)
}

// 事件列表
func EventNames() []string {
    return NewEvents().EventNames()
}

// 事件对应监听列表
func EventListeners(name any) []*EventListener {
    return NewEvents().EventListeners(name)
}
