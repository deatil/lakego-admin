package events

import (
    "strings"
)

// 接口
type IActionSubscribe interface {
    Subscribe(*Action)
}

type Action struct {
    Event
}

func NewAction() *Action {
    return &Action{
        Event: Event{
            listener: make(map[string][]Listener),
            pool:     NewPool(),
        },
    }
}

// 注册事件订阅者
func (this *Action) Subscribe(subscribers ...any) *Action {
    if len(subscribers) == 0 {
        return this
    }

    for _, subscriber := range subscribers {
        switch t := subscriber.(type) {
        case IActionSubscribe:
            t.Subscribe(this)
        default:
            this.Observe(subscriber, "", 1)
        }
    }

    return this
}

func (this *Action) Trigger(event any, params ...any) {
    this.mu.RLock()
    defer this.mu.RUnlock()

    eventName := formatName(event)
    if this.pool.IsStruct(event) {
        params = append([]any{event}, params...)
    }

    listeners := this.listener[eventName]

    if _, ok := event.(string); ok {
        if strings.Contains(eventName, ".") {
            events := strings.SplitN(eventName, ".", 2)

            for e, listener := range this.listener {
                if events[1] == "*" && strings.HasPrefix(e, events[0] + ".") {
                    listeners = append(listeners, listener...)
                }
            }
        }
    }

    this.listenerSort(listeners, "desc")

    for _, listener := range listeners {
        this.dispatch(listener.Listener, params)
    }
}
