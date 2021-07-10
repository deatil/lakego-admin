package event

import (
    "github.com/gin-gonic/gin"
    
    "lakego-admin/lakego/event"
)

// 在中间件初始化事件
func Event() gin.HandlerFunc {
    return func(ctx *gin.Context) {
        /*
        dispatcher := event.NewEventDispatcher()
        listener := event.NewEventListener(myEventListener)
        dispatcher.AddEventListener("event", listener)
        
        //dispatcher.RemoveEventListener("event", listener)
        
        dispatcher.DispatchEvent(event.NewEvent("event", nil))
        */

        dispatcher := event.NewEventDispatcher()
        ctx.Set("event", dispatcher)
        
        // 当前事件
        cevent, _ := ctx.Get("event")
        cevent.(*event.EventDispatcher).DispatchEvent(event.NewEvent("event_init", nil))
    
        ctx.Next()
    }
}
