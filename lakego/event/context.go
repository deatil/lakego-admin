package event

import (
    "github.com/gin-gonic/gin"
)

/**
 * 绑定到上下文
 *
 * @create 2021-8-20
 * @author deatil
 */
func ContextBind(ctx *gin.Context) {
    dispatcher := NewEventDispatcher()
    ctx.Set("event", dispatcher)
}

// 监听
func ContextEvent(ctx *gin.Context, name string, handler EventHandler) {
    listener := NewEventListener(handler)

    // 当前事件
    cevent, _ := ctx.Get("event")
    cevent.(*EventDispatcher).AddEventListener(name, listener)
}

// 移除
func ContextRemove(ctx *gin.Context, name string, handler EventHandler) bool {
    listener := NewEventListener(handler)

    // 当前事件
    cevent, _ := ctx.Get("event")
    return cevent.(*EventDispatcher).RemoveEventListener(name, listener)
}

// 判断存在
func ContextHas(ctx *gin.Context, eventType string) bool {
    // 当前事件
    cevent, _ := ctx.Get("event")
    return cevent.(*EventDispatcher).HasEventListener(eventType)
}

// 事件调度
func ContextDispatch(ctx *gin.Context, name string, object ...interface{}) bool {
    // 当前事件
    cevent, _ := ctx.Get("event")

    var eventObject interface{}
    if len(object) > 0 {
        eventObject = object[0]
    }

    return cevent.(*EventDispatcher).DispatchEvent(NewEvent(name, eventObject))
}

