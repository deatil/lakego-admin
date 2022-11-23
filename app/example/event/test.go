package event

import (
    "github.com/deatil/go-event/event"

    "github.com/deatil/lakego-doak/lakego/facade/logger"
)

type TestEvent struct {}

func (this *TestEvent) OnTestEvent(data any) {
    logger.New().Info("1-TestEvent: ")
    logger.New().Info(data)
}

func (this *TestEvent) OnTestEventName(data any, name string) {
    logger.New().Info("2-TestEventName start: ")
    logger.New().Info(data)
    logger.New().Info(name)
    logger.New().Info("2-TestEventName end: ")
}

func (this *TestEvent) OnTestEvents(e *event.Event) {
    logger.New().Info("===== 3-TestEvents start: =====")
    logger.New().Info(e.Object)
    logger.New().Info(e.Type)
    logger.New().Info("===== 3-TestEvents end: =====")
}

type TestEventPrefix struct {}

func (this TestEventPrefix) EventPrefix() string {
    return "ABC"
}

func (this TestEventPrefix) OnTestEvent(data any) {
    logger.New().Info("4-TestEventPrefix: ")
    logger.New().Info(data)
}

type TestEventSubscribe struct {}

func (this *TestEventSubscribe) Subscribe(e *event.Events) {
    e.Listen("TestEventSubscribe", this.OnTestEvent)
}

func (this *TestEventSubscribe) OnTestEvent(data any) {
    logger.New().Info("5-TestEventSubscribe: ")
    logger.New().Info(data)
}

// ====================

type TestEventStructData struct {
    Data string
}

func TestEventStruct(data any) {
    if newData, ok := data.(TestEventStructData); ok {
        logger.New().Info("6-TestEventStruct: ")
        logger.New().Info(newData.Data)
    }
}
