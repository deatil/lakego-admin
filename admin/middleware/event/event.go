package event

import (
    "github.com/gin-gonic/gin"

    "lakego-admin/lakego/event"
)

// 在中间件初始化事件
func Handler() gin.HandlerFunc {
    return func(ctx *gin.Context) {
        // 绑定初始事件
        event.ContextBind(ctx)

        // 事件调度
        event.ContextDispatch(ctx, "event_init")
    }
}
