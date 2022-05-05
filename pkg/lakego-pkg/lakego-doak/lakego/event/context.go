package event

import (
    "github.com/deatil/lakego-doak/lakego/router"
)

/**
 * 绑定到上下文
 *
 * @create 2021-8-20
 * @author deatil
 */
func ContextBind(ctx *router.Context) {
    dispatcher := NewEventDispatcher()
    ctx.Set("event", dispatcher)
}

// 监听
func ContextEvent(ctx *router.Context, name string, handler EventHandler) {
    listener := NewEventListener(handler)

    // 当前事件
    cevent, _ := ctx.Get("event")
    cevent.(*EventDispatcher).AddEventListener(name, listener)
}

// 移除
func ContextRemove(ctx *router.Context, name string, handler EventHandler) bool {
    listener := NewEventListener(handler)

    // 当前事件
    cevent, _ := ctx.Get("event")
    return cevent.(*EventDispatcher).RemoveEventListener(name, listener)
}

// 判断存在
func ContextHas(ctx *router.Context, eventType string) bool {
    // 当前事件
    cevent, _ := ctx.Get("event")
    return cevent.(*EventDispatcher).HasEventListener(eventType)
}

// 事件调度
func ContextDispatch(ctx *router.Context, name string, object ...any) bool {
    // 当前事件
    cevent, _ := ctx.Get("event")

    var eventObject any
    if len(object) > 0 {
        eventObject = object[0]
    }

    return cevent.(*EventDispatcher).DispatchEvent(NewEvent(name, eventObject))
}

