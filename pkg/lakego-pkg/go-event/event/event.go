package event

import (
	"fmt"
	"reflect"
)

// 监听器函数
// EventHandler func
type EventHandler = func(*Event)

// 监听器
// Event Listener
type EventListener struct {
	Handler EventHandler
}

// 创建监听器
// New Event Listener
func NewEventListener(h EventHandler) *EventListener {
	l := new(EventListener)
	l.Handler = h
	return l
}

// 事件调度器中存放的单元
// Event Saver list
type EventSaver struct {
	// 类型
	Type string

	// 监听器
	Listeners []*EventListener
}

// 事件调度接口
// EventDispatcher interface
type IEventDispatcher interface {
	// 事件监听
	AddEventListener(string, *EventListener)

	// 移除事件监听
	RemoveEvent(string) bool

	// 是否包含事件
	HasEvent(string) bool

	// 移除事件监听
	RemoveEventListener(string, *EventListener) bool

	// 是否包含事件
	HasEventListener(string, *EventListener) bool

	// 事件派发
	DispatchEvent(*Event)
}

// =====

/**
 * 事件 / Event
 *
 * @create 2021-8-20
 * @author deatil
 */
type Event struct {
	// 事件触发实例 / target struct
	Target IEventDispatcher

	// 事件类型 / type
	Type string

	// 事件携带数据源 / event data
	Object any
}

// 创建事件
// New Event
func NewEvent(eventType string, object any) *Event {
	e := &Event{
		Type:   eventType,
		Object: object,
	}

	return e
}

// 克隆事件
// Clone Event
func (this *Event) Clone() *Event {
	e := new(Event)
	e.Type = this.Type
	e.Target = this.Target

	return e
}

// 返回字符
// return string
func (this *Event) String() string {
	return fmt.Sprintf("Event Type %v", this.Type)
}

// =====

// 事件调度器
// Event Dispatcher
type EventDispatcher struct {
	savers []*EventSaver
}

// 创建事件派发器
// New Event Dispatcher
func NewEventDispatcher() *EventDispatcher {
	dispatcher := new(EventDispatcher)
	dispatcher.savers = make([]*EventSaver, 0)

	return dispatcher
}

// 事件调度器添加事件
// Add Event Listener
func (this *EventDispatcher) AddEventListener(eventType string, listener *EventListener) {
	for _, saver := range this.savers {
		if saver.Type == eventType {
			saver.Listeners = append(saver.Listeners, listener)
			return
		}
	}

	saver := &EventSaver{
		Type:      eventType,
		Listeners: []*EventListener{listener},
	}

	this.savers = append(this.savers, saver)
}

// 移除事件
// Remove Event
func (this *EventDispatcher) RemoveEvent(eventType string) bool {
	for i, saver := range this.savers {
		if saver.Type == eventType {
			this.savers = append(this.savers[:i], this.savers[i+1:]...)

			return true
		}
	}

	return false
}

// 是否有定义事件
// if has Event return true or return false
func (this *EventDispatcher) HasEvent(eventType string) bool {
	for _, saver := range this.savers {
		if saver.Type == eventType {
			return true
		}
	}

	return false
}

// 事件调度器移除某个监听
// Remove Listen
func (this *EventDispatcher) RemoveEventListener(eventType string, listener *EventListener) bool {
	for _, saver := range this.savers {
		if saver.Type == eventType {
			for i, l := range saver.Listeners {
				if reflect.DeepEqual(listener, l) {
					saver.Listeners = append(saver.Listeners[:i], saver.Listeners[i+1:]...)
					return true
				}
			}
		}
	}

	return false
}

// 是否存在
// if has Listen return true or return false
func (this *EventDispatcher) HasEventListener(eventType string, listener *EventListener) bool {
	for _, saver := range this.savers {
		if saver.Type == eventType {
			for _, l := range saver.Listeners {
				if reflect.DeepEqual(listener, l) {
					return true
				}
			}
		}
	}

	return false
}

// 事件调度器派发事件
// Dispatch Event
func (this *EventDispatcher) DispatchEvent(event *Event) {
	for _, saver := range this.savers {
		if matchTypeName(event.Type, saver.Type) {
			for _, listener := range saver.Listeners {
				event.Target = this

				listener.Handler(event)
			}
		}
	}
}

// 事件类型列表
// Event name list
func (this *EventDispatcher) EventNames() []string {
	names := make([]string, 0)

	for _, saver := range this.savers {
		names = append(names, saver.Type)
	}

	return names
}

// 事件类型对应监听列表
// list Event Listeners
func (this *EventDispatcher) EventListeners(eventType string) []*EventListener {
	for _, saver := range this.savers {
		if saver.Type == eventType {
			return saver.Listeners
		}
	}

	return nil
}
