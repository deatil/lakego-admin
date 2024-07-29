package events

// 默认事件
// default new events
var defaultEvent = New()

// 默认事件
// default new events
func Default() *Events {
    return defaultEvent
}

// 注册操作
// Add Action
func AddAction(event any, listener any, sort int) {
    defaultEvent.Action().Listen(event, listener, sort)
}

// 触发操作
// Do Action
func DoAction(event any, params ...any) {
    defaultEvent.Action().Trigger(event, params...)
}

// 移除操作
// Remove Action
func RemoveAction(event string, listener any, sort int) bool {
    return defaultEvent.Action().RemoveListener(event, listener, sort)
}

// 是否有操作
// Has Action
func HasAction(event string, listener any) bool {
    return defaultEvent.Action().HasListener(event, listener)
}

// 注册过滤器
// Add Filter
func AddFilter(event any, listener any, sort int) {
    defaultEvent.Filter().Listen(event, listener, sort)
}

// 触发过滤器
// Apply Filters
func ApplyFilters(event any, params ...any) any {
    return defaultEvent.Filter().Trigger(event, params...)
}

// 移除过滤器
// Remove Filter
func RemoveFilter(event string, listener any, sort int) bool {
    return defaultEvent.Filter().RemoveListener(event, listener, sort)
}

// 是否有过滤器
// Has Filter
func HasFilter(event string, listener any) bool {
    return defaultEvent.Filter().HasListener(event, listener)
}
