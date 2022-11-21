package event

import(
    "sync"
    "strings"
    "reflect"
)

var instance *Events
var once sync.Once

// 单例模式
func NewEvents() *Events {
    once.Do(func() {
        instance = &Events{
            dispatcher: NewEventDispatcher(),
        }
    })

    return instance
}

/**
 * 事件
 *
 * @create 2022-11-20
 * @author deatil
 */
type Events struct {
    dispatcher *EventDispatcher
}

// 监听
func (this *Events) listen(name string, handler EventHandler) {
    listener := NewEventListener(handler)

    this.dispatcher.AddEventListener(name, listener)
}

// 监听
func (this *Events) subscribeListen(es EventSubscribe, e *Event) {
    fn := es.Method.Func

    fnType := fn.Type()

    numIn := fnType.NumIn()

    // 参数
    params := make([]reflect.Value, 0)
    params = append(params, es.Struct)

    switch numIn {
        case 2:
            if fnType.In(1).String() == "interface {}" {
                params = append(params, reflect.ValueOf(e.Object))
            } else if fnType.In(1).String() == "*event.Event" {
                params = append(params, reflect.ValueOf(e))
            }
        case 3:
            if fnType.In(1).String() == "interface {}" && fnType.In(2).String() == "string" {
                params = append(params, reflect.ValueOf(e.Object))
                params = append(params, reflect.ValueOf(e.Type))
            }
    }

    if len(params) == numIn {
        fn.Call(params)
    }
}

// 监听
func (this *Events) Listen(name string, handler any) {
    switch fn := handler.(type) {
        // func(*Event)
        case EventHandler:
            this.listen(name, fn)

        case func(any):
            this.listen(name, func(e *Event) {
                fn(e.Object)
            })

        case func(any, string):
            this.listen(name, func(e *Event) {
                fn(e.Object, e.Type)
            })

        case EventSubscribe:
            this.listen(name, func(e *Event) {
                this.subscribeListen(fn, e)
            })
    }
}

// 注册事件订阅者
func (this *Events) Subscribe(subscribers ...any) *Events {
    if len(subscribers) == 0 {
        return this
    }

    for _, subscriber := range subscribers {
        switch t := subscriber.(type) {
            case ISubscribe:
                t.Subscribe(this)
            default:
                this.Observe(subscriber, "")
        }
    }

    return this
}

// 自动注册事件观察者
// observer 观察者
// prefix   事件名前缀
func (this *Events) Observe(observer any, prefix string) *Events {
    observerKind := reflect.TypeOf(observer).Kind()
    if observerKind != reflect.Struct || observerKind != reflect.Pointer {
        switch t := observer.(type) {
            case ISubscribePrefix:
                prefix = t.EventPrefix()
        }

        observerObject := reflect.TypeOf(observer)
        for i := 0; i < observerObject.NumMethod(); i++ {
            name := observerObject.Method(i).Name

            if strings.HasPrefix(name, "On") {
                this.Listen(prefix + name[2:], EventSubscribe{
                    reflect.ValueOf(observer),
                    observerObject.Method(i),
                })
            }
        }
    }

    return this
}

// 事件调度
func (this *Events) Dispatch(name string, object ...any) bool {
    var eventObject any
    if len(object) > 0 {
        eventObject = object[0]
    }

    cevent := NewEvent(name, eventObject)

    return this.dispatcher.DispatchEvent(cevent)
}

// 移除
func (this *Events) Remove(name string, handler any) bool {
    var newHandler EventHandler

    switch fn := handler.(type) {
        // func(*Event)
        case EventHandler:
            newHandler = fn

        case func(any):
            newHandler = func(e *Event) {
                fn(e.Object)
            }

        case func(any, string):
            newHandler = func(e *Event) {
                fn(e.Object, e.Type)
            }

        case EventSubscribe:
            newHandler = func(e *Event) {
                this.subscribeListen(fn, e)
            }
    }

    listener := NewEventListener(newHandler)

    return this.dispatcher.RemoveEventListener(name, listener)
}

// 判断存在
func (this *Events) Has(name string) bool {
    return this.dispatcher.HasEventListener(name)
}
