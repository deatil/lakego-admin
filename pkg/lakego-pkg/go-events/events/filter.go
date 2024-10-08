package events

import (
	"strings"
)

// 接口
// Filter Subscribe interface
type IFilterSubscribe interface {
	Subscribe(*Filter)
}

// Filter
type Filter struct {
	Event
}

// New Filter and retrun *Filter
func NewFilter() *Filter {
	return &Filter{
		Event: Event{
			listener: make(map[string][]Listener),
			pool:     NewPool(),
		},
	}
}

// 注册事件订阅者
// Subscribe
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

// Trigger func
func (this *Filter) Trigger(event any, params ...any) any {
	this.mu.RLock()
	defer this.mu.RUnlock()

	var value any

	eventName := formatName(event)

	if this.pool.IsStruct(event) {
		value = event
	} else {
		if len(params) == 0 {
			panic("go-events: Filter trigger func need value")
		}

		value = params[0]
		params = params[1:]
	}

	listeners := this.listener[eventName]

	if _, ok := event.(string); ok {
		if strings.Contains(eventName, ".*") {
			needSort := false
			events := strings.SplitN(eventName, ".", 2)

			for e, listener := range this.listener {
				if events[1] == "*" && strings.HasPrefix(e, events[0]+".") {
					listeners = append(listeners, listener...)
					needSort = true
				}
			}

			if needSort {
				this.listenerSort(listeners, "desc")
			}
		}
	}

	tmp := params
	result := value
	for _, listener := range listeners {
		tmp = append([]any{result}, tmp...)

		result = this.dispatch(listener.Listener, tmp)
		tmp = params
	}

	return result
}
