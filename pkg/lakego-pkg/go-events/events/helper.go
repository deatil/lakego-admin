package events

// 注册操作
func AddAction(event any, listener any, sort int) {
    Default.Action().Listen(event, listener, sort)
}

// 触发操作
func DoAction(event any, params ...any) {
    Default.Action().Trigger(event, params...)
}

// 移除操作
func RemoveAction(event string, listener any, sort int) bool {
    return Default.Action().RemoveListener(event, listener, sort)
}

// 是否有操作
func HasAction(event string, listener any) bool {
    return Default.Action().HasListener(event, listener)
}

// 注册过滤器
func AddFilter(event any, listener any, sort int) {
    Default.Filter().Listen(event, listener, sort)
}

// 触发过滤器
func ApplyFilters(event any, params ...any) any {
    return Default.Filter().Trigger(event, params...)
}

// 移除过滤器
func RemoveFilter(event string, listener any, sort int) bool {
    return Default.Filter().RemoveListener(event, listener, sort)
}

// 是否有过滤器
func HasFilter(event string, listener any) bool {
    return Default.Filter().HasListener(event, listener)
}
