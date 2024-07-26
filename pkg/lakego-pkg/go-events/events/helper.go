package events

// 注册操作
func AddAction(event any, listener any, sort int) {
    DefaultAction.Listen(event, listener, sort)
}

// 触发操作
func DoAction(event any, params ...any) {
    DefaultAction.Trigger(event, params...)
}

// 移除操作
func RemoveAction(event string, listener any, sort int) bool {
    return DefaultAction.RemoveListener(event, listener, sort)
}

// 是否有操作
func HasAction(event string, listener any) bool {
    return DefaultAction.HasListener(event, listener)
}

// 注册过滤器
func AddFilter(event any, listener any, sort int) {
    DefaultFilter.Listen(event, listener, sort)
}

// 触发过滤器
func ApplyFilters(event any, value any, params ...any) any {
    return DefaultFilter.Trigger(event, value, params...)
}

// 移除过滤器
func RemoveFilter(event string, listener any, sort int) bool {
    return DefaultFilter.RemoveListener(event, listener, sort)
}

// 是否有过滤器
func HasFilter(event string, listener any) bool {
    return DefaultFilter.HasListener(event, listener)
}
