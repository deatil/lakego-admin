package event

import (
    "github.com/deatil/go-event/event"

    "github.com/deatil/lakego-doak/lakego/facade"
)

type TestEvent struct {}

func (this *TestEvent) OnTestEvent(data any) {
    facade.Logger.Info("1-TestEvent: ")
    facade.Logger.Info(data)
}

func (this *TestEvent) OnTestEventName(data string, name any) {
    facade.Logger.Info("2-TestEventName start: ")
    facade.Logger.Info(data)
    facade.Logger.Info(name)
    facade.Logger.Info("2-TestEventName end: ")
}

func (this *TestEvent) OnTestEvents(e *event.Event, name string) {
    facade.Logger.Info("===== 3-TestEvents start: =====")
    facade.Logger.Info(e.Object)
    facade.Logger.Info(e.Type)
    facade.Logger.Info(name)
    facade.Logger.Info("===== 3-TestEvents end: =====")
}

type TestEventPrefix struct {}

func (this TestEventPrefix) EventPrefix() string {
    return "ABC"
}

func (this TestEventPrefix) OnTestEvent(data any) {
    facade.Logger.Info("4-TestEventPrefix: ")
    facade.Logger.Info(data)
}

type TestEventSubscribe struct {}

func (this *TestEventSubscribe) Subscribe(e *event.Events) {
    e.Listen("TestEventSubscribe", this.OnTestEvent)
}

func (this *TestEventSubscribe) OnTestEvent(data any) {
    facade.Logger.Info("5-TestEventSubscribe: ")
    facade.Logger.Info(data)
}

// ====================

type TestEventStructData struct {
    Data string
}

func TestEventStruct(data TestEventStructData, name any) {
    facade.Logger.Info("6-TestEventStruct: ")
    facade.Logger.Info(data.Data)
    facade.Logger.Info(name)
}

// ====================

type TestEventStructHandle struct {}

func (this *TestEventStructHandle) Handle(data any) {
    facade.Logger.Info("7-TestEventStructHandle: ")
    facade.Logger.Info(data)
}
