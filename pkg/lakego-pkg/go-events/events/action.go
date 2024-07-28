package events

import (
    "strings"
)

// Action Subscribe interface
type IActionSubscribe interface {
    Subscribe(*Action)
}

// Action event
type Action struct {
    Event
}

// new Action event
func NewAction() *Action {
    return &Action{
        Event: Event{
            listener: make(map[string][]Listener),
            pool:     NewPool(),
        },
    }
}

// 注册事件订阅者
// Subscribe
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

// Trigger funcs
func (this *Action) Trigger(event any, params ...any) {
    this.mu.RLock()
    defer this.mu.RUnlock()

    eventName := formatName(event)

    listeners := this.listener[eventName]

    if _, ok := event.(string); ok {
        if strings.Contains(eventName, ".*") {
            needSort := false
            events := strings.SplitN(eventName, ".", 2)

            for e, listener := range this.listener {
                if events[1] == "*" && strings.HasPrefix(e, events[0] + ".") {
                    listeners = append(listeners, listener...)
                    needSort = true
                }
            }

            if needSort {
                this.listenerSort(listeners, "desc")
            }
        }
    }

    for _, listener := range listeners {
        this.dispatch(listener.Listener, params)
    }
}
