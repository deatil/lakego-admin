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
func RemoveListen(name any, handler EventHandler) bool {
    return NewEvents().Remove(name, handler)
}

// 判断存在
func HasListen(name any) bool {
    return NewEvents().Has(name)
}
