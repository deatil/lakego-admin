package events

import (
    "sort"
    "sync"
    "strings"
    "reflect"
)

// 前缀接口
type ISubscribePrefix interface {
    EventPrefix() string
}

// 排序接口
type ISubscribeSort interface {
    EventSort() int
}

// 监听器数据
type Listener struct {
    Listener any
    Sort     int
    Key      string
}

type Event struct {
    mu       sync.RWMutex
    listener map[string][]Listener
    pool     *Pool
}

// 自动注册事件观察者 / add observer
// observer 观察者 / observer user
// prefix   事件名前缀 / event prefix
func (this *Event) Observe(observer any, prefix string, sort int) *Event {
    observerKind := reflect.TypeOf(observer).Kind()
    if observerKind != reflect.Struct && observerKind != reflect.Pointer {
        return this
    }

    if ob, ok := observer.(ISubscribePrefix); ok {
        prefix = ob.EventPrefix()
    }

    if ob, ok := observer.(ISubscribeSort); ok {
        sort = ob.EventSort()
    }

    observerObject := reflect.TypeOf(observer)
    observerVal := reflect.ValueOf(observer)
    for i := 0; i < observerObject.NumMethod(); i++ {
        name := observerObject.Method(i).Name

        if strings.HasPrefix(name, "On") {
            method := observerVal.MethodByName(name)

            this.Listen(prefix + name[2:], method, sort)
        }
    }

    return this
}

// 注册事件监听
func (this *Event) Listen(event any, listener any, sort int) {
    this.mu.Lock()
    defer this.mu.Unlock()

    eventName := formatName(event)

    if _, ok := this.listener[eventName]; !ok {
        this.listener[eventName] = make([]Listener, 0)
    }

    this.listener[eventName] = append(this.listener[eventName], Listener{
        Listener: listener,
        Sort:     sort,
        Key:      formatName(listener),
    })
}

// 移除监听事件
func (this *Event) RemoveListener(event string, listener any, sort int) bool {
    this.mu.Lock()
    defer this.mu.Unlock()

    key := formatName(listener)

    _, exists := this.listener[event]
    if exists {
        for k, v := range this.listener[event] {
            if v.Key == key && v.Sort == sort {
                this.listener[event] = append(this.listener[event][:k], this.listener[event][k+1:]...)
            }
        }
    }

    return exists
}

// 事件是否在监听
func (this *Event) HasListener(event string, listener any) bool {
    if listener == nil {
        return this.HasListeners()
    }

    this.mu.RLock()
    defer this.mu.RUnlock()

    if _, exists := this.listener[event]; !exists {
        return false
    }

    key := formatName(listener)
    if key == "" {
        return false
    }

    for _, listen := range this.listener[event] {
        if listen.Key == key {
            return true
        }
    }

    return false
}

// 是否有事件监听
func (this *Event) HasListeners() bool {
    this.mu.RLock()
    defer this.mu.RUnlock()

    for _, listener := range this.listener {
        if len(listener) > 0 {
            return true
        }
    }

    return false
}

// 获取所有事件监听
func (this *Event) GetListeners() map[string][]Listener {
    this.mu.RLock()
    defer this.mu.RUnlock()

    return this.listener
}

// 是否存在事件监听点
func (this *Event) Exists(event string) bool {
    this.mu.RLock()
    defer this.mu.RUnlock()

    if _, exists := this.listener[event]; exists {
        return true
    }

    return false
}

// 移除事件监听点
func (this *Event) Remove(event string) {
    this.mu.Lock()
    defer this.mu.Unlock()

    delete(this.listener, event)
}

// 清空
func (this *Event) Clear() {
    this.mu.Lock()
    defer this.mu.Unlock()

    this.listener = make(map[string][]Listener)
}

// 执行事件调度
func (this *Event) dispatch(event any, params []any) any {
    if this.pool.IsFunc(event) {
        return this.pool.CallFunc(event, params)
    } else if eventMethod, ok := event.(reflect.Value); ok {
        return this.pool.Call(eventMethod, params)
    } else {
        method := "Handle"

        return this.pool.CallStructMethod(event, method, params)
    }
}

// 排序
func (this *Event) listenerSort(listeners []Listener, typ string) {
    sort.Slice(listeners, func(i, j int) bool {
        if typ == "desc" {
            return listeners[i].Sort > listeners[j].Sort
        } else {
            return listeners[i].Sort < listeners[j].Sort
        }
    })
}

