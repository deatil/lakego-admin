package event

import (
    "fmt"
)

// 创建事件派发器
func NewEventDispatcher() *EventDispatcher {
    return new(EventDispatcher)
}

// 创建监听器
func NewEventListener(h EventHandler) *EventListener {
    l := new(EventListener)
    l.Handler = h
    return l
}

// 创建事件
func NewEvent(eventType string, object interface{}) Event {
    e := Event{
        Type: eventType,
        Object: object,
    }
    return e
}

// =====

// 监听器函数
type EventHandler func(Event)

// 监听器
type EventListener struct {
    Handler EventHandler
}

// 事件调度器中存放的单元
type EventSaver struct {
    // 类型
    Type      string

    // 监听器
    Listeners []*EventListener
}

// 事件调度接口
type IEventDispatcher interface {
    // 事件监听
    AddEventListener(string, *EventListener)

    // 移除事件监听
    RemoveEventListener(string, *EventListener) bool

    // 是否包含事件
    HasEventListener(string) bool

    // 事件派发
    DispatchEvent(Event) bool
}

// =====

/**
 * 事件
 *
 * @create 2021-8-20
 * @author deatil
 */
type Event struct {
    // 事件触发实例
    Target IEventDispatcher

    // 事件类型
    Type string

    // 事件携带数据源
    Object interface{}
}

// 克隆事件
func (this *Event) Clone() *Event {
    e := new(Event)
    e.Type = this.Type
    e.Target = e.Target
    return e
}

// 返回字符
func (this *Event) ToString() string {
    return fmt.Sprintf("Event Type %v", this.Type)
}

// =====

// 事件调度器
type EventDispatcher struct {
    savers []*EventSaver
}

// 事件调度器添加事件
func (this *EventDispatcher) AddEventListener(eventType string, listener *EventListener) {
    for _, saver := range this.savers {
        if saver.Type == eventType {
            saver.Listeners = append(saver.Listeners, listener)
            return
        }
    }

    saver := &EventSaver{Type:eventType, Listeners:[]*EventListener{listener}}
    this.savers = append(this.savers, saver)
}

// 事件调度器移除某个监听
func (this *EventDispatcher) RemoveEventListener(eventType string, listener *EventListener) bool {
    for _, saver := range this.savers {
        if saver.Type == eventType {
            for i, l := range saver.Listeners {
                if listener == l {
                    saver.Listeners = append(saver.Listeners[:i], saver.Listeners[i + 1:]...)
                    return true
                }
            }
        }
    }

    return false
}

// 事件调度器是否包含某个类型的监听
func (this *EventDispatcher) HasEventListener(eventType string) bool {
    for _, saver := range this.savers {
        if saver.Type == eventType {
            return true
        }
    }

    return false
}

// 事件调度器派发事件
func (this *EventDispatcher) DispatchEvent(event Event) bool {
    for _, saver := range this.savers {
        if saver.Type == event.Type {
            for _, listener := range saver.Listeners {
                event.Target = this
                listener.Handler(event)
            }
            return true
        }
    }

    return false
}
