### 事件使用

## 触发事件

~~~go
import "github.com/deatil/lakego-doak/lakego/event"

// 触发事件
var eventData any
event.Dispatch("data.error", eventData)

// 触发 `data.` 为前缀的全部事件
event.Dispatch("data.*", eventData)
~~~

## 添加监听事件

添加事件通常都在服务提供者添加

~~~go
import "github.com/deatil/lakego-doak/lakego/event"

// 添加监听事件
// 方式1
event.Listen("data.error", func(data any) {
    // fmt.Println(data)
})

// 方式2
event.Listen("data.error", func(data any, eventName string) {
    // fmt.Println(eventName)
    // fmt.Println(data)
})

// 方式2
event.Listen("data.error", func(e *Event) {
    // eventName = e.Type
    // fmt.Println(e.Type)   

    // data = e.Object
    // fmt.Println(e.Object) 
})
~~~
