package event

import (
	"reflect"
	"strings"
	"sync"
)

// 默认事件
// default new events
var defaultEvents = New()

/**
 * 事件 / Events
 *
 * @create 2022-11-20
 * @author deatil
 */
type Events struct {
	// 读写锁 / read or write Mutex
	mu sync.RWMutex

	// 调度器 / dispatcher struct
	dispatcher *EventDispatcher
}

// 构造函数
// New Events
func New() *Events {
	event := &Events{
		dispatcher: NewEventDispatcher(),
	}

	return event
}

// 监听
// Listen event
func (this *Events) Listen(name any, handler any) {
	this.mu.Lock()
	defer this.mu.Unlock()

	newName := formatName(name)
	if newName != "" {
		listener := this.formatEventHandler(handler)

		this.dispatcher.AddEventListener(newName, listener, false)
	}
}

// 监听
// Listen event
func Listen(name any, handler any) {
	defaultEvents.Listen(name, handler)
}

// 置前监听
// PreListen event
func (this *Events) PreListen(name any, handler any) {
	this.mu.Lock()
	defer this.mu.Unlock()

	newName := formatName(name)
	if newName != "" {
		listener := this.formatEventHandler(handler)

		this.dispatcher.AddEventListener(newName, listener, true)
	}
}

// 置前监听
// PreListen event
func PreListen(name any, handler any) {
	defaultEvents.PreListen(name, handler)
}

// 注册事件订阅者
// add Subscribe
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

// 注册事件订阅者
// add Subscribe
func Subscribe(subscribers ...any) {
	defaultEvents.Subscribe(subscribers...)
}

// 自动注册事件观察者 / add observer
// observer 观察者 / observer user
// prefix   事件名前缀 / event prefix
func (this *Events) Observe(observer any, prefix string) *Events {
	observerKind := reflect.TypeOf(observer).Kind()
	if observerKind != reflect.Struct && observerKind != reflect.Pointer {
		return this
	}

	if ob, ok := observer.(ISubscribePrefix); ok {
		prefix = ob.EventPrefix()
	}

	observerObject := reflect.TypeOf(observer)
    observerVal := reflect.ValueOf(observer)
	for i := 0; i < observerObject.NumMethod(); i++ {
		name := observerObject.Method(i).Name

		if strings.HasPrefix(name, "On") {
            method := observerVal.MethodByName(name)

			this.Listen(prefix+name[2:], method)
		}
	}

	return this
}

// 注册事件观察者
// add observer
func Observe(observer any, prefix string) {
	defaultEvents.Observe(observer, prefix)
}

// 事件调度
// Dispatch Event
func (this *Events) Dispatch(name any, object any, once bool) any {
	this.mu.RLock()
	defer this.mu.RUnlock()

	var newName string

	if n, ok := name.(string); ok {
		newName = n
	} else {
		// 为结构体时
		// when Struct
		nameKind := reflect.TypeOf(name).Kind()
		if nameKind == reflect.Struct || nameKind == reflect.Pointer {
			newName = getStructName(name)
			object = name
		}
	}

	if newName == "" {
		return nil
	}

	newEvent := NewEvent(newName, object)
	res := this.dispatcher.DispatchEvent(newEvent, once)

	return res
}

// 事件调度
// Dispatch Event
func Dispatch(name any, object any, once bool) any {
	return defaultEvents.Dispatch(name, object, once)
}

// 触发事件(只获取一个有效返回值)
func (this *Events) Until(name any, object any) any {
	return this.Dispatch(name, object, true)
}

// 触发事件(只获取一个有效返回值)
func Until(name any, object any) any {
	return defaultEvents.Until(name, object)
}

// 移除
// Remove Event
func (this *Events) RemoveEvent(name any) bool {
	this.mu.RLock()
	defer this.mu.RUnlock()

	newName := formatName(name)
	if newName == "" {
		return false
	}

	return this.dispatcher.RemoveEvent(newName)
}

// 移除
// Remove Event
func RemoveEvent(name any) bool {
	return defaultEvents.RemoveEvent(name)
}

// 判断存在
// if has Event return true or return false
func (this *Events) HasEvent(name any) bool {
	this.mu.RLock()
	defer this.mu.RUnlock()

	newName := formatName(name)
	if newName == "" {
		return false
	}

	return this.dispatcher.HasEvent(newName)
}

// 判断存在
// if has Event return true or return false
func HasEvent(name any) bool {
	return defaultEvents.HasEvent(name)
}

// 移除
// Remove Listen
func (this *Events) RemoveListen(name any, handler any) bool {
	this.mu.RLock()
	defer this.mu.RUnlock()

	newName := formatName(name)
	if newName == "" {
		return false
	}

	listener := this.formatEventHandler(handler)

	return this.dispatcher.RemoveEventListener(newName, listener)
}

// 移除
// Remove Listen
func RemoveListen(name any, handler any) bool {
	return defaultEvents.RemoveListen(name, handler)
}

// 判断存在
// if has Listen return true or return false
func (this *Events) HasListen(name any, handler any) bool {
	this.mu.RLock()
	defer this.mu.RUnlock()

	newName := formatName(name)
	if newName == "" {
		return false
	}

	listener := this.formatEventHandler(handler)

	return this.dispatcher.HasEventListener(newName, listener)
}

// 判断存在
// if has Listen return true or return false
func HasListen(name any, handler any) bool {
	return defaultEvents.HasListen(name, handler)
}

// 事件列表
// Event name list
func (this *Events) EventNames() []string {
	this.mu.RLock()
	defer this.mu.RUnlock()

	return this.dispatcher.EventNames()
}

// 事件列表
// Event name list
func EventNames() []string {
	return defaultEvents.EventNames()
}

// 事件对应监听列表
// list Event Listeners
func (this *Events) EventListeners(name any) []*EventListener {
	this.mu.RLock()
	defer this.mu.RUnlock()

	newName := formatName(name)
	if newName == "" {
		return []*EventListener{}
	}

	return this.dispatcher.EventListeners(newName)
}

// 事件对应监听列表
// list Event Listeners
func EventListeners(name any) []*EventListener {
	return defaultEvents.EventListeners(name)
}

// 重置
// Reset Event
func (this *Events) Reset() *Events {
	this.dispatcher = NewEventDispatcher()

	return this
}

// 重置
// Reset Event
func Reset() {
	defaultEvents.Reset()
}

// 订阅监听
// subscribe Listen
func (this *Events) subscribeListen(fn reflect.Value, e *Event) any {
	fnType := fn.Type()

	numIn := fnType.NumIn()

	// 参数
	params := make([]reflect.Value, 0)

	switch numIn {
	case 1:
		if getTypeName(fnType.In(0)) == getStructName(&Event{}) {
			params = append(params, reflect.ValueOf(e))
		} else {
			dataValue := this.convertTo(fnType.In(0), e.Object)
			params = append(params, dataValue)
		}
	case 2:
		if getTypeName(fnType.In(0)) == getStructName(&Event{}) {
			params = append(params, reflect.ValueOf(e))
		} else {
			dataValue := this.convertTo(fnType.In(0), e.Object)
			params = append(params, dataValue)
		}

		nameValue := this.convertTo(fnType.In(1), e.Type)
		params = append(params, nameValue)
	}

	if len(params) == numIn {
		res := fn.Call(params)
		if len(res) > 0 {
			return res[0].Interface()
		}
	}

	return nil
}

// 函数反射监听
// listen func
func (this *Events) funcReflectListen(fn any, e *Event) any {
	fnObject := reflect.ValueOf(fn)

	if !(fnObject.IsValid() && fnObject.Kind() == reflect.Func) {
		return nil
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
		res := fnObject.Call(newParams)
		if len(res) > 0 {
			return res[0].Interface()
		}
	}

	return nil
}

// 结构体方法反射监听
// listen struct
func (this *Events) structHandleReflectListen(fn any, e *Event) any {
	method := "Handle"

	// 获取到方法
	newMethod := reflect.ValueOf(fn).MethodByName(method)

	return this.subscribeListen(newMethod, e)
}

// 格式化
// format Event Handler
func (this *Events) formatEventHandler(handler any) *EventListener {
	var newHandler EventHandler

	switch fn := handler.(type) {
	case *EventListener:
		return fn

	// func(*Event) any
	case EventHandler:
		newHandler = fn

	case func() any:
		newHandler = func(e *Event) any {
			return fn()
		}

	case func(any) any:
		newHandler = func(e *Event) any {
			return fn(e.Object)
		}

	case func(any, string) any:
		newHandler = func(e *Event) any {
			return fn(e.Object, e.Type)
		}

	case reflect.Value:
		newHandler = func(e *Event) any {
			return this.subscribeListen(fn, e)
		}

	default:
		fnKind := reflect.TypeOf(fn).Kind()

		if fnKind == reflect.Func {
			newHandler = func(e *Event) any {
				return this.funcReflectListen(fn, e)
			}
		} else if fnKind == reflect.Struct || fnKind == reflect.Pointer {
			newHandler = func(e *Event) any {
				return this.structHandleReflectListen(fn, e)
			}
		}

	}

	listener := NewEventListener(newHandler)

	return listener
}

// 转换类型
// src convert type to new typ
func (this *Events) convertTo(typ reflect.Type, src any) reflect.Value {
	dataKey := getTypeName(typ)

	fieldType := reflect.TypeOf(src)
	if !fieldType.ConvertibleTo(typ) {
		return reflect.New(typ).Elem()
	}

	fieldValue := reflect.ValueOf(src)

	if dataKey != getTypeName(fieldType) {
		// 转换类型
		// Convert type
		fieldValue = fieldValue.Convert(typ)
	}

	return fieldValue
}
