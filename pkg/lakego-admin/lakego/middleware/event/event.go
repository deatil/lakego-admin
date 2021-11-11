package event

import (
    gin "github.com/deatil/lakego-admin/lakego/router"
    "github.com/deatil/lakego-admin/lakego/event"
)

/**
 * 在中间件初始化事件
 *
 * @create 2021-9-8
 * @author deatil
 */
func Handler() gin.HandlerFunc {
    return func(ctx *gin.Context) {
        // 绑定初始事件
        event.ContextBind(ctx)

        // 事件调度
        event.ContextDispatch(ctx, "event_init")
    }
}
