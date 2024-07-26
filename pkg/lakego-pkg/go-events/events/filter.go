package events

import (
    "strings"
)

// 接口
type IFilterSubscribe interface {
    Subscribe(*Filter)
}

type Filter struct {
    Event
}

func NewFilter() *Filter {
    return &Filter{
        Event: Event{
            listener: make(map[string][]Listener),
            pool:     NewPool(),
        },
    }
}

// 注册事件订阅者
func (this *Filter) Subscribe(subscribers ...any) *Filter {
    if len(subscribers) == 0 {
        return this
    }

    for _, subscriber := range subscribers {
        switch t := subscriber.(type) {
        case IFilterSubscribe:
            t.Subscribe(this)
        default:
            this.Observe(subscriber, "", 1)
        }
    }

    return this
}

func (this *Filter) Trigger(event any, value any, params ...any) any {
    this.mu.RLock()
    defer this.mu.RUnlock()

    eventName := formatName(event)
    if this.pool.IsStruct(event) {
        value = event
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

    tmp := params
    result := value
    for _, listener := range listeners {
        tmp = append([]any{result}, tmp...)

        result = this.dispatch(listener.Listener, tmp)
        tmp = params
    }

    return result
}
