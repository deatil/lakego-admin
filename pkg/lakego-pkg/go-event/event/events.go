package event

import(
    "sync"
    "strings"
    "reflect"
)

// 构造函数
func NewEvents() *Events {
    event := &Events{
        dispatcher: NewEventDispatcher(),
    }

    return event
}

/**
 * 事件
 *
 * @create 2022-11-20
 * @author deatil
 */
type Events struct {
    // 锁定
    mu sync.RWMutex

    // 调度器
    dispatcher *EventDispatcher
}

// 监听
func (this *Events) Listen(name any, handler any) {
    this.mu.Lock()
    defer this.mu.Unlock()

    newName := FormatName(name)
    if newName != "" {
        listener := this.formatEventHandler(handler)

        this.dispatcher.AddEventListener(newName, listener)
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
    if observerKind != reflect.Struct && observerKind != reflect.Pointer {
        return this
    }

    if ob, ok := observer.(ISubscribePrefix); ok {
        prefix = ob.EventPrefix()
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

    return this
}

// 事件调度
func (this *Events) Dispatch(name any, object ...any) bool {
    this.mu.RLock()
    defer this.mu.RUnlock()

    var eventObject any
    if len(object) > 0 {
        eventObject = object[0]
    }

    var newName string

    if n, ok := name.(string); ok {
        newName = n
    } else {
        // 为结构体时
        nameKind := reflect.TypeOf(name).Kind()
        if nameKind == reflect.Struct || nameKind == reflect.Pointer {
            newName = GetStructName(name)
            eventObject = name
        }
    }

    if newName == "" {
        return false
    }

    newEvent := NewEvent(newName, eventObject)

    return this.dispatcher.DispatchEvent(newEvent)
}

// 移除
func (this *Events) RemoveEvent(name any) bool {
    this.mu.RLock()
    defer this.mu.RUnlock()

    newName := FormatName(name)
    if newName == "" {
        return false
    }

    return this.dispatcher.RemoveEvent(newName)
}

// 判断存在
func (this *Events) HasEvent(name any) bool {
    this.mu.RLock()
    defer this.mu.RUnlock()

    newName := FormatName(name)
    if newName == "" {
        return false
    }

    return this.dispatcher.HasEvent(newName)
}

// 移除
func (this *Events) RemoveListen(name any, handler any) bool {
    this.mu.RLock()
    defer this.mu.RUnlock()

    newName := FormatName(name)
    if newName == "" {
        return false
    }

    listener := this.formatEventHandler(handler)

    return this.dispatcher.RemoveEventListener(newName, listener)
}

// 判断存在
func (this *Events) HasListen(name any, handler any) bool {
    this.mu.RLock()
    defer this.mu.RUnlock()

    newName := FormatName(name)
    if newName == "" {
        return false
    }

    listener := this.formatEventHandler(handler)

    return this.dispatcher.HasEventListener(newName, listener)
}

// 事件列表
func (this *Events) EventNames() []string {
    this.mu.RLock()
    defer this.mu.RUnlock()

    return this.dispatcher.EventNames()
}

// 事件对应监听列表
func (this *Events) EventListeners(name any) []*EventListener {
    this.mu.RLock()
    defer this.mu.RUnlock()

    newName := FormatName(name)
    if newName == "" {
        return nil
    }

    return this.dispatcher.EventListeners(newName)
}

// 重置
func (this *Events) Reset() *Events {
    this.dispatcher = NewEventDispatcher()

    return this
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
            if GetTypeKey(fnType.In(1)) == GetStructName(&Event{}) {
                params = append(params, reflect.ValueOf(e))
            } else {
                dataValue := this.convertTo(fnType.In(1), e.Object)
                params = append(params, dataValue)
            }
        case 3:
            if GetTypeKey(fnType.In(1)) == GetStructName(&Event{}) {
                params = append(params, reflect.ValueOf(e))
            } else {
                dataValue := this.convertTo(fnType.In(1), e.Object)
                params = append(params, dataValue)
            }

            nameValue := this.convertTo(fnType.In(2), e.Type)
            params = append(params, nameValue)
    }

    if len(params) == numIn {
        fn.Call(params)
    }
}

// 函数反射监听
func (this *Events) funcReflectListen(fn any, e *Event) {
    fnObject := reflect.ValueOf(fn)

    if !(fnObject.IsValid() && fnObject.Kind() == reflect.Func) {
        return
    }

    valueType := fnObject.Type()
    fieldNum := valueType.NumIn()

    newParams := make([]reflect.Value, 0)

    switch fieldNum {
        case 1:
            dataValue := this.convertTo(valueType.In(0), e.Object)
            newParams = append(newParams, dataValue)

        case 2:
            dataValue := this.convertTo(valueType.In(0), e.Object)
            newParams = append(newParams, dataValue)

            nameValue := this.convertTo(valueType.In(1), e.Type)
            newParams = append(newParams, nameValue)
    }

    if fieldNum == len(newParams) {
        fnObject.Call(newParams)
    }
}

// 结构体方法反射监听
func (this *Events) structHandleReflectListen(fn any, e *Event) {
    method := "Handle"

    // 获取到方法
    newMethod, ok := reflect.TypeOf(fn).MethodByName(method)
    if !ok {
        return
    }

    this.subscribeListen(EventSubscribe{
        reflect.ValueOf(fn),
        newMethod,
    }, e)
}

// 格式化
func (this *Events) formatEventHandler(handler any) *EventListener {
    var newHandler EventHandler

    switch fn := handler.(type) {
        // func(*Event)
        case EventHandler:
            newHandler = fn

        case func():
            newHandler = func(e *Event) {
                fn()
            }

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

        default:
            fnKind := reflect.TypeOf(fn).Kind()

            if fnKind == reflect.Func {
                newHandler = func(e *Event) {
                    this.funcReflectListen(fn, e)
                }
            } else if fnKind == reflect.Struct || fnKind == reflect.Pointer {
                newHandler = func(e *Event) {
                    this.structHandleReflectListen(fn, e)
                }
            }

    }

    listener := NewEventListener(newHandler)

    return listener
}

// 格式化
func (this *Events) convertTo(src reflect.Type, dst any) reflect.Value {
    dataKey := GetTypeKey(src)

    fieldType := reflect.TypeOf(dst)
    if !fieldType.ConvertibleTo(src) {
        return reflect.New(src).Elem()
    }

    fieldValue := reflect.ValueOf(dst)

    if dataKey != GetTypeKey(fieldType) {
        // 转换类型
        fieldValue = fieldValue.Convert(src)
    }

    return fieldValue
}
