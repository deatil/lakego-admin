package event

import (
	"fmt"
	"reflect"
	"testing"
)

func assertDeepEqualT(t *testing.T) func(any, any, string) {
	return func(actual any, expected any, msg string) {
		if !reflect.DeepEqual(actual, expected) {
			t.Errorf("Failed %s: actual: %v, expected: %v", msg, actual, expected)
		}
	}
}

func Test_Listen(t *testing.T) {
	eq := assertDeepEqualT(t)

	checkData := "index data"
	var eventData, eventData_2, eventData_3, eventData_33, eventData_5 any

	Listen("data.test", func(data any) {
		eventData = data
	})
	Listen("data.test", func(data any) {
		eventData_2 = data
	})
	Listen("data.test", func(data any, name string) {
		eventData_3 = name
	})
	Listen("data.test", func() {
		eventData_33 = "eventData_33"
	})
	Listen("data.test", func(e *Event) {
		eventData_5 = e.Object
	})
	Dispatch("data.test", checkData)

	eq(eventData, checkData, "Listen")
	eq(eventData_2, checkData, "Listen eventData_2")
	eq(eventData_3, "data.test", "Listen eventData_3")
	eq(eventData_33, "eventData_33", "Listen eventData_33")
	eq(eventData_5, checkData, "Listen eventData_5")

	// ==========

	checkData2 := "index data 222"
	var eventData2 any

	ev := New()

	ev.Listen("data.test111111", func(data any) {
		eventData2 = data
	})
	ev.Dispatch("data.test111111", checkData2)

	eq(eventData2, checkData2, "Listen2")

	// ==========

	checkData3 := "index data many"
	var eventData3, eventData3_1, eventData3_2 any

	Listen("many.test1", func(data any) {
		eventData3 = data
	})
	Listen("many.test2", func(data any) {
		eventData3_1 = data
	})
	Listen("many.test3", func(data any) {
		eventData3_2 = data
	})
	Dispatch("many.*", checkData3)

	eq(eventData3, checkData3, "Listen eventData3")
	eq(eventData3_1, checkData3, "Listen eventData3_1")
	eq(eventData3_2, checkData3, "Listen eventData3_2")
}

func Test_RemoveAndHasEvent(t *testing.T) {
	eq := assertDeepEqualT(t)

	checkData := "index data Test_RemoveAndHasEvent"
	var eventData, eventData_2 any

	Listen("remove.test", func(data any) {
		eventData = data
	})
	Listen("remove.test2", func(data any) {
		eventData_2 = data
	})

	eq(HasEvent("remove.test2"), true, "Test_RemoveAndHasEvent HasEvent 0")

	RemoveEvent("remove.test2")

	Dispatch("remove.test", checkData)
	Dispatch("remove.test2", checkData)

	eq(eventData, checkData, "Test_RemoveAndHasEvent")
	eq(eventData_2, nil, "Test_RemoveAndHasEvent")

	eq(HasEvent("remove.test"), true, "Test_RemoveAndHasEvent HasEvent 1")
	eq(HasEvent("remove.test2"), false, "Test_RemoveAndHasEvent HasEvent 2")

	evnames := EventNames()
	eq(fmt.Sprintf("%v", evnames), "[data.test many.test1 many.test2 many.test3 remove.test]", "Test_RemoveAndHasEvent EventNames")

	eq(RemoveEvent(float32(123123)), false, "Test_RemoveAndHasEvent RemoveEvent other type")
	eq(HasEvent(float32(123123)), false, "Test_RemoveAndHasEvent HasEvent other type")

	// ========

	checkData2 := "index data Test_RemoveAndHasEvent 222"
	var eventData2, eventData2_2 any

	ev := New()

	ev.Listen("remove2.test", func(data any) {
		eventData2 = data
	})
	ev.Listen("remove2.test2", func(data any) {
		eventData2_2 = data
	})

	eq(ev.HasEvent("remove2.test2"), true, "Test_RemoveAndHasEvent2 HasEvent 0")

	ev.RemoveEvent("remove2.test2")

	ev.Dispatch("remove2.test", checkData2)
	ev.Dispatch("remove2.test2", checkData2)

	eq(eventData2, checkData2, "Test_RemoveAndHasEvent2")
	eq(eventData2_2, nil, "Test_RemoveAndHasEvent2 nil")

	eq(ev.HasEvent("remove2.test"), true, "Test_RemoveAndHasEvent2 HasEvent 1")
	eq(ev.HasEvent("remove2.test2"), false, "Test_RemoveAndHasEvent2 HasEvent 2")
}

func Test_ListenFunc(t *testing.T) {
	eq := assertDeepEqualT(t)

	checkData66 := 123123
	var eventData66 any

	Listen("func.test1", func(data int) {
		eventData66 = data
	})
	Dispatch("func.test1", checkData66)

	eq(eventData66, checkData66, "Listen eventData66")

}

var testEventRes map[string]any

func init() {
	testEventRes = make(map[string]any)
}

type TestEvent struct{}

func (this *TestEvent) OnTestEvent(data any) {
	testEventRes["TestEvent_OnTestEvent"] = data
}

func (this *TestEvent) OnTestEventName(data any, name string) {
	testEventRes["TestEvent_OnTestEventName"] = data
	testEventRes["TestEvent_OnTestEventNameName"] = name
}

type TestEventPrefix struct{}

func (this TestEventPrefix) EventPrefix() string {
	return "ABC"
}

func (this TestEventPrefix) OnTestEvent(data any) {
	testEventRes["TestEventPrefix_OnTestEvent"] = data
}

type TestEventPrefix2 struct{}

func (this TestEventPrefix2) OnTestEvent(data any) {
	testEventRes["TestEventPrefix2_OnTestEvent"] = data
}

type TestEventSubscribe struct{}

func (this *TestEventSubscribe) Subscribe(e *Events) {
	e.Listen("TestEventSubscribe", this.OnTestEvent)
}

func (this *TestEventSubscribe) OnTestEvent(data any) {
	testEventRes["TestEventSubscribe_OnTestEvent"] = data
}

type TestEventStructData struct {
	Data string
}

func EventStructTest(data TestEventStructData, name any) {
	testEventRes["EventStructTest"] = data.Data
	testEventRes["EventStructTest_Name"] = name
}

type TestEventStructHandle struct{}

func (this *TestEventStructHandle) Handle(data any) {
	testEventRes["TestEventStructHandle_Handle"] = data
}

func Test_Subscribe(t *testing.T) {
	eq := assertDeepEqualT(t)

	checkData := "index data Test_Subscribe"

	// when empty
	Subscribe()

	Subscribe(&TestEvent{})
	Dispatch("TestEvent", checkData)
	Dispatch("TestEventName", checkData)

	// when other type
	eq(Dispatch(float64(556677)), false, "Dispatch other type")

	eq(testEventRes["TestEvent_OnTestEvent"], checkData, "Subscribe 1")
	eq(testEventRes["TestEvent_OnTestEventName"], checkData, "Subscribe 2")
	eq(testEventRes["TestEvent_OnTestEventNameName"], "TestEventName", "Subscribe 2")

	// =======

	ev := New()

	checkData2 := "index data Test_Subscribe 2"

	ev.Subscribe(&TestEvent{})
	ev.Dispatch("TestEvent", checkData2)
	ev.Dispatch("TestEventName", checkData2)

	eq(testEventRes["TestEvent_OnTestEvent"], checkData2, "Subscribe 2-1")
	eq(testEventRes["TestEvent_OnTestEventName"], checkData2, "Subscribe 2-2")
	eq(testEventRes["TestEvent_OnTestEventNameName"], "TestEventName", "Subscribe Name 2-2")
}

func Test_Subscribe_Prefix(t *testing.T) {
	eq := assertDeepEqualT(t)

	checkData := "index data Test_Subscribe_Prefix"

	Subscribe(TestEventPrefix{})
	Dispatch("ABCTestEvent", checkData)

	eq(testEventRes["TestEventPrefix_OnTestEvent"], checkData, "Subscribe 1")

	// =======

	ev := New()

	checkData2 := "index data Test_Subscribe_Prefix 2"

	ev.Subscribe(TestEventPrefix{})
	ev.Dispatch("ABCTestEvent", checkData2)

	eq(testEventRes["TestEventPrefix_OnTestEvent"], checkData2, "Subscribe 2-1")

	// =======

	checkData22 := "index data Test_Subscribe_Prefix2 2"

	Observe("awefr", "ACS")

	Observe(TestEventPrefix2{}, "ACS")
	Dispatch("ACSTestEvent", checkData22)

	eq(testEventRes["TestEventPrefix2_OnTestEvent"], checkData22, "Observe TestEventPrefix2 2-1")
}

func Test_EventSubscribe(t *testing.T) {
	eq := assertDeepEqualT(t)

	checkData := "index data Test_EventSubscribe"

	Subscribe(&TestEventSubscribe{})
	Dispatch("TestEventSubscribe", checkData)

	eq(testEventRes["TestEventSubscribe_OnTestEvent"], checkData, "Subscribe 1")

	// =======

	ev := New()

	checkData2 := "index data Test_EventSubscribe 2"

	ev.Subscribe(&TestEventSubscribe{})
	ev.Dispatch("TestEventSubscribe", checkData2)

	eq(testEventRes["TestEventSubscribe_OnTestEvent"], checkData2, "Subscribe 2-1")
}

func Test_EventStruct(t *testing.T) {
	eq := assertDeepEqualT(t)

	checkData := "index data Test_EventStruct"

	Listen(TestEventStructData{}, EventStructTest)
	Dispatch(TestEventStructData{
		Data: checkData,
	})

	eq(testEventRes["EventStructTest"], checkData, "Subscribe 1")
	eq(testEventRes["EventStructTest_Name"], "github.com/deatil/go-event/event.TestEventStructData", "Subscribe Name 2-2")

	// =======

	ev := New()

	checkData2 := "index data Test_EventStruct 2"

	ev.Listen(TestEventStructData{}, EventStructTest)
	ev.Dispatch(TestEventStructData{
		Data: checkData2,
	})

	eq(testEventRes["EventStructTest"], checkData2, "Subscribe 2-1")
	eq(testEventRes["EventStructTest_Name"], "github.com/deatil/go-event/event.TestEventStructData", "Subscribe Name 2-2")
}

func Test_EventStructHandle(t *testing.T) {
	eq := assertDeepEqualT(t)

	checkData := "index data Test_EventStructHandle"

	Listen("TestEventStructHandle", &TestEventStructHandle{})
	Dispatch("TestEventStructHandle", checkData)

	eq(testEventRes["TestEventStructHandle_Handle"], checkData, "Subscribe 1")

	// =======

	ev := New()

	checkData2 := "index data Test_EventStructHandle 2"

	ev.Listen("TestEventStructHandle", &TestEventStructHandle{})
	ev.Dispatch("TestEventStructHandle", checkData2)

	eq(testEventRes["TestEventStructHandle_Handle"], checkData2, "Subscribe 2-1")
}

func Test_Event(t *testing.T) {
	eq := assertDeepEqualT(t)

	checkData := "index data Test_Event"

	ev1 := NewEvent("data.test", checkData)
	ev2 := ev1.Clone()

	eq(ev2.String(), ev1.String(), "Test_Event")
}

func Test_RemoveListen(t *testing.T) {
	eq := assertDeepEqualT(t)

	checkData := "index data"
	var eventData any

	fn1 := func(data any) {
		eventData = data
	}

	Listen("data22222.test", fn1)

	eq(HasListen("data22222.test", fn1), false, "RemoveListen")
	eq(HasListen(int64(123678), fn1), false, "RemoveListen other type")

	Dispatch("data22222.test", checkData)

	eq(eventData, checkData, "RemoveListen")

	// ==========

	ev := NewEventDispatcher()

	listener := NewEventListener(func(e *Event) {})

	ev.AddEventListener("data22222.test111111", listener)
	eq(ev.HasEventListener("data22222.test111111", listener), true, "HasEventListener")

	eventListeners := ev.EventListeners("data22222.test111111")
	eq(eventListeners, []*EventListener{listener}, "EventListeners")

	ev.RemoveEventListener("data22222.test111111", listener)
	eq(ev.HasEventListener("data22222.test111111", listener), false, "RemoveEventListener")

	// ==========

	listener2 := NewEventListener(func(e *Event) {})

	Listen("RemoveListen2.test111111", listener2)
	eq(HasListen("RemoveListen2.test111111", listener2), true, "HasListen 2")

	eventListeners2 := EventListeners("RemoveListen2.test111111")
	eq(eventListeners2, []*EventListener{listener2}, "EventListeners 2")

	RemoveListen("RemoveListen2.test111111", listener2)
	eq(HasListen("RemoveListen2.test111111", listener2), false, "RemoveListen 2")
}

func Test_Reset(t *testing.T) {
	eq := assertDeepEqualT(t)

	checkData := "index data Reset"
	var eventData any

	Listen("Reset.test", func(data any) {
		eventData = data
	})
	Reset()
	Dispatch("Reset.test", checkData)

	eq(eventData, nil, "Reset")

	// ==========

	checkData2 := "index data 222"
	var eventData2 any

	ev := New()

	ev.Listen("Reset.test111111", func(data any) {
		eventData2 = data
	})
	ev.Reset()
	ev.Dispatch("Reset.test111111", checkData2)

	eq(eventData2, nil, "Reset 2")
}
