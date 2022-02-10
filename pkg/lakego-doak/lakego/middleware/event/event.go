package event

import (
    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/event"
)

/**
 * 在中间件初始化事件
 *
 * @create 2021-9-8
 * @author deatil
 */
func Handler() router.HandlerFunc {
    return func(ctx *router.Context) {
        // 绑定初始事件
        event.ContextBind(ctx)

        // 事件调度
        event.ContextDispatch(ctx, "event_init")
    }
}
