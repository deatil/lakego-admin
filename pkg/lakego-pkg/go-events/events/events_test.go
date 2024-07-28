package events

import (
    "fmt"
    "reflect"
    "testing"
)

var testEventRes map[string]any

func init() {
    testEventRes = make(map[string]any)
}

func Test_Helper_Action(t *testing.T) {
    eq := assertDeepEqualT(t)

    test := ""

    AddAction("test1", func() {
        test = "run test1"
    }, DefaultSort)
    DoAction("test1")

    eq(test, "run test1", "AddAction")

    // =========

    test2 := ""

    AddAction("test2", func() {
        test2 = "run test2"
    }, DefaultSort)
    AddAction("test2", func() {
        test2 += " doing"
    }, DefaultSort)
    DoAction("test2")

    eq(test2, "run test2 doing", "AddAction 2")

    // =========

    listener3 := func() {
        test2 = "run test2"
    }

    AddAction("test3", listener3, DefaultSort)
    eq(HasAction("test3", listener3), true, "HasAction")

    RemoveAction("test3", listener3, DefaultSort)
    eq(HasAction("test3", listener3), false, "RemoveAction")

    // =========

    test5 := ""

    listener5 := func(val string) {
        test5 = "run test5 " + val
    }
    AddAction("test5", listener5, DefaultSort)

    data5 := "init5"
    DoAction("test5", data5)

    eq(test5, "run test5 init5", "AddAction val")
}

func Test_Helper_Filter(t *testing.T) {
    eq := assertDeepEqualT(t)

    AddFilter("test1", func(val string) string {
        return "run test1 => " + val
    }, DefaultSort)

    data1 := "init1"
    test := ApplyFilters("test1", data1)

    eq(test, "run test1 => init1", "AddFilter")

    // =========

    AddFilter("test2", func(val string) string {
        return val + " run test2"
    }, DefaultSort)
    AddFilter("test2", func(val string) string {
        return val + " doing"
    }, DefaultSort)

    data2 := "init2"
    test2 := ApplyFilters("test2", data2)

    eq(test2, "init2 run test2 doing", "AddFilter 2")

    // =========

    listener3 := func(val string) {
        test2 = "run test2"
    }

    AddFilter("test3", listener3, DefaultSort)
    eq(HasFilter("test3", listener3), true, "HasFilter")

    RemoveFilter("test3", listener3, DefaultSort)
    eq(HasFilter("test3", listener3), false, "RemoveFilter")

    // =========

    listener5 := func(val string, arg1 string) string {
        return "run test5 " + val + " => arg: [" + arg1 + "]"
    }
    AddFilter("test5", listener5, DefaultSort)

    data5 := "init5"
    arg5 := "dodododo"
    test5 := ApplyFilters("test5", data5, arg5)

    eq(test5, "run test5 init5 => arg: [dodododo]", "AddFilter val")
}

type TestEventStructHandle struct{}

func (this *TestEventStructHandle) Handle(data string) string {
    return "run " + data
}

func Test_Helper_Struct(t *testing.T) {
    eq := assertDeepEqualT(t)

    AddFilter("test6", &TestEventStructHandle{}, DefaultSort)

    data1 := "init6"
    test := ApplyFilters("test6", data1)

    eq(test, "run init6", "AddFilter")
}

type TestEventPrefix2 struct{}

func (this TestEventPrefix2) OnTestEvent(data any) {
    testEventRes["TestEventPrefix2_OnTestEvent"] = data
}

func Test_EventPrefix2(t *testing.T) {
    eq := assertDeepEqualT(t)

    action := NewAction()
    action.Subscribe(TestEventPrefix2{})

    data1 := "init6"
    action.Trigger("TestEvent", data1)

    eq(testEventRes["TestEventPrefix2_OnTestEvent"], "init6", "Subscribe")
}

type TestEventSubscribe struct{}

func (this *TestEventSubscribe) Subscribe(e *Action) {
    e.Listen("TestEventSubscribe", this.OnTestEvent, DefaultSort)
}

func (this *TestEventSubscribe) OnTestEvent(data any) {
    testEventRes["TestEventSubscribe_OnTestEvent"] = data
}

type TestEventSubscribeFilter struct{}

func (this *TestEventSubscribeFilter) Subscribe(e *Filter) {
    e.Listen("TestEventSubscribeFilter", this.OnTestEvent, DefaultSort)
}

func (this *TestEventSubscribeFilter) OnTestEvent(data string) string {
    return "TestEventSubscribeFilter => " + data
}

func Test_EventSubscribe(t *testing.T) {
    eq := assertDeepEqualT(t)

    action := NewAction()
    action.Subscribe(&TestEventSubscribe{})

    data1 := "init6-88888"
    action.Trigger("TestEventSubscribe", data1)

    eq(testEventRes["TestEventSubscribe_OnTestEvent"], "init6-88888", "TestEventSubscribe")

    // =========

    filter := NewFilter()
    filter.Subscribe(&TestEventSubscribeFilter{})

    data2 := "init7-88888"
    res := filter.Trigger("TestEventSubscribeFilter", data2)

    eq(res, "TestEventSubscribeFilter => init7-88888", "TestEventSubscribeFilter")

    // =========

    {
        filter := NewFilter()
        filter.Subscribe()

        data2 := "init7-88888"
        res := filter.Trigger("TestEventSubscribeFilter", data2)

        eq(res, "init7-88888", "TestEventSubscribeFilter 2")
    }
}

func Test_Events(t *testing.T) {
    eq := assertDeepEqualT(t)

    action := NewAction()

    test3 := ""
    listener3 := func(val string) {
        test3 = "run test3" + val
    }

    action.Listen("test3", listener3, DefaultSort)
    eq(action.HasListener("test3", listener3), true, "HasListener")
    eq(action.HasListener("test3", nil), true, "HasListener nil")
    eq(action.HasListeners(), true, "HasListeners")

    listeners := action.GetListeners()
    eq(len(listeners), 1, "GetListeners")

    eq(action.Exists("test3"), true, "Exists")

    action.Remove("test3")
    eq(action.Exists("test3"), false, "Remove")

    listeners2 := action.GetListeners()
    eq(len(listeners2), 0, "GetListeners 2")

    action.RemoveListener("test3", listener3, DefaultSort)
    eq(action.HasListener("test3", listener3), false, "RemoveListener")
    eq(action.HasListener("test3", nil), false, "HasListener nil 2")
    eq(action.HasListeners(), false, "HasListeners 2")

    data3 := "data3"
    action.Trigger("test3", data3)

    eq(test3, "", "Test_Events")

    // ========

    action2 := NewAction()

    listener32 := func(val string) {}
    action2.Listen("test3", listener32, DefaultSort)

    listeners3 := action2.GetListeners()
    eq(len(listeners3), 1, "GetListeners 3")

    action2.Clear()

    listeners33 := action2.GetListeners()
    eq(len(listeners33), 0, "GetListeners 33")
}

type TestEventPrefix struct{}

func (this TestEventPrefix) EventPrefix() string {
	return "ABC"
}

func (this TestEventPrefix) OnTestEvent(data any) {
	testEventRes["TestEventPrefix_OnTestEvent"] = data
}

func Test_EventPrefix(t *testing.T) {
    eq := assertDeepEqualT(t)

    action := NewAction()
    action.Subscribe(TestEventPrefix{})
    action.Subscribe()

    data1 := "init77"
    action.Trigger("ABCTestEvent", data1)

    eq(testEventRes["TestEventPrefix_OnTestEvent"], "init77", "Test_EventPrefix")
}

func Test_EventSort(t *testing.T) {
    eq := assertDeepEqualT(t)

    action := NewAction()

    test3 := ""
    listener3 := func() {
        test3 += "run test3 => "
    }
    listener33 := func() {
        test3 += "run test33 => "
    }
    listener5 := func() {
        test3 += "run test5 => "
    }

    action.Listen("test3", listener3, 1)
    action.Listen("test3", listener33, 6)
    action.Listen("test3", listener5, 5)

    action.Trigger("test3")

    check := "run test33 => run test5 => run test3 => "
    eq(test3, check, "Test_EventSort")
}

var TestEventPrefixData = ""

type TestEventPrefix11 struct{}

func (this TestEventPrefix11) EventPrefix() string {
	return "ABC"
}

func (this TestEventPrefix11) EventSort() int {
	return 5
}

func (this TestEventPrefix11) OnTestEvent() {
	TestEventPrefixData += "2222222"
}

type TestEventPrefix12 struct{}

func (this TestEventPrefix12) EventPrefix() string {
	return "ABC"
}

func (this TestEventPrefix12) EventSort() int {
	return 3
}

func (this TestEventPrefix12) OnTestEvent() {
	TestEventPrefixData += "333333"
}

func Test_EventPrefixAndSort(t *testing.T) {
    eq := assertDeepEqualT(t)

    action := NewAction()
    action.Subscribe(TestEventPrefix12{})
    action.Subscribe(TestEventPrefix11{})

    action.Trigger("ABCTestEvent")

    eq(TestEventPrefixData, "2222222333333", "Test_EventPrefixAndSort")
}

type TestEventStructData struct {}

func DTestEventStruct(data string) {
	testEventRes["DTestEventStruct"] = data
}

func Test_EventStructData(t *testing.T) {
    eq := assertDeepEqualT(t)

    action := NewAction()

    // 事件注册
    action.Listen(TestEventStructData{}, DTestEventStruct, DefaultSort)

    // 事件触发
    eventData2 := "index data"
    action.Trigger(TestEventStructData{}, eventData2)

    eq(testEventRes["DTestEventStruct"], eventData2, "Test_EventStructData")
}

type TestEventStructDataFilter struct {
    Data string
}

func DTestEventStructFilter(data TestEventStructDataFilter, arg string) string {
	return data.Data + " => " + arg
}

func Test_EventStructDataFilter(t *testing.T) {
    eq := assertDeepEqualT(t)

    filter := NewFilter()

    // 事件注册
    filter.Listen(TestEventStructDataFilter{}, DTestEventStructFilter, DefaultSort)

    // 事件触发
    initData := "init"
    args := "index data"
    res := filter.Trigger(TestEventStructDataFilter{
        Data: initData,
    }, args)

    check := "init => index data"
    eq(res, check, "Test_EventStructDataFilter")
}

func Test_FilterPanic(t *testing.T) {
    defer func() {
        if e := recover(); e == nil {
            t.Error("should panic error")
        }
    }()

    filter := NewFilter()

    // 事件注册
    filter.Listen("panic", func(val string) string {
        return val
    }, DefaultSort)

    _ = filter.Trigger("panic")
}

func testReflectValueFunc(val string) {
    testEventRes["testReflectValueFunc"] = val
}

func Test_ReflectValue(t *testing.T) {
    eq := assertDeepEqualT(t)

    action := NewAction()
    action.Listen("Test_ReflectValue", reflect.ValueOf(testReflectValueFunc), DefaultSort)

    data1 := "init6"
    action.Trigger("Test_ReflectValue", data1)

    eq(testEventRes["testReflectValueFunc"], "init6", "Test_ReflectValue")
}

func Test_Struct_fail(t *testing.T) {
    eq := assertDeepEqualT(t)

    defer func() {
        if e := recover(); e != nil {
            err := fmt.Sprintf("%v", e)

            check := "go-events: struct type error"
            eq(err, check, "Struct failed")
        }
    }()

    action := NewAction()
    action.Listen("Test_Struct_fail", "testReflectValueFunc", DefaultSort)

    data1 := "init6"
    action.Trigger("Test_Struct_fail", data1)
}

func Test_Struct_fail_2(t *testing.T) {
    eq := assertDeepEqualT(t)

    defer func() {
        if e := recover(); e != nil {
            err := fmt.Sprintf("%v", e)

            check := "go-events: struct type error"
            eq(err, check, "Struct failed 2")
        }
    }()

    action := NewAction()
    action.Listen("Test_Struct_fail_2", reflect.ValueOf("testReflectValueFunc"), DefaultSort)

    data1 := "init6"
    action.Trigger("Test_Struct_fail_2", data1)
}

func Test_ActionStar(t *testing.T) {
    eq := assertDeepEqualT(t)

    action := NewAction()

    test3 := ""
    listener3 := func() {
        test3 += "run test3 => "
    }
    listener33 := func() {
        test3 += "run test33 => "
    }
    listener5 := func() {
        test3 += "run test5 => "
    }

    action.Listen("test3.a", listener3, 1)
    action.Listen("test3.b", listener33, 6)
    action.Listen("test3.c", listener5, 5)

    action.Trigger("test3.*")

    check := "run test33 => run test5 => run test3 => "
    eq(test3, check, "Test_ActionStar")
}

func Test_FilterStar(t *testing.T) {
    eq := assertDeepEqualT(t)

    filter := NewFilter()

    listener3 := func(val string) string {
        return val + "run test3 => "
    }
    listener33 := func(val string) string {
        return val + "run test33 => "
    }
    listener5 := func(val string) string {
        return val + "run test5 => "
    }

    filter.Listen("test3.a", listener3, 1)
    filter.Listen("test3.b", listener33, 6)
    filter.Listen("test3.c", listener5, 5)

    init := "init => "
    test3 := filter.Trigger("test3.*", init)

    check := "init => run test33 => run test5 => run test3 => "
    eq(test3, check, "Test_FilterStar")
}

func Test_ActionSort(t *testing.T) {
    eq := assertDeepEqualT(t)

    action := NewAction()

    test3 := ""
    listener3 := func() {
        test3 += "run test3 => "
    }
    listener33 := func() {
        test3 += "run test33 => "
    }
    listener5 := func() {
        test3 += "run test5 => "
    }

    action.Listen("Test_ActionSort", listener3, 1)
    action.Listen("Test_ActionSort", listener33, 6)
    action.Listen("Test_ActionSort", listener5, 5)

    action.Trigger("Test_ActionSort")

    check := "run test33 => run test5 => run test3 => "
    eq(test3, check, "Test_ActionStar")
}

func Test_FilterSort(t *testing.T) {
    eq := assertDeepEqualT(t)

    filter := NewFilter()

    listener3 := func(val string) string {
        return val + "run test22 => "
    }
    listener33 := func(val string) string {
        return val + "run test33 => "
    }
    listener5 := func(val string) string {
        return val + "run test55 => "
    }

    filter.Listen("Test_FilterSort", listener3, 1)
    filter.Listen("Test_FilterSort", listener33, 6)
    filter.Listen("Test_FilterSort", listener5, 5)

    init := "init => "
    test3 := filter.Trigger("Test_FilterSort", init)

    check := "init => run test33 => run test55 => run test22 => "
    eq(test3, check, "Test_FilterStar")
}

type TestEventStructHandleAny struct{}

func (this *TestEventStructHandleAny) Handlerrr(data string) string {
    return "run " + data
}

func Test_Filter_Any(t *testing.T) {
    eq := assertDeepEqualT(t)

    {
        filter := NewFilter()
        filter.Listen("Test_Filter_Any", []any{
            &TestEventStructHandleAny{},
            "Handlerrr",
        }, DefaultSort)

        init := "init6 => "
        res := filter.Trigger("Test_Filter_Any", init)

        eq(res, "run init6 => ", "Test_Filter_Any")
    }

    {
        filter := NewFilter()
        filter.Listen("Test_Filter_Any", []any{
            reflect.ValueOf(&TestEventStructHandleAny{}),
            "Handlerrr",
        }, DefaultSort)

        init := "init7 => "
        res := filter.Trigger("Test_Filter_Any", init)

        eq(res, "run init7 => ", "Test_Filter_Any 2")
    }
}

type TestEventActionHandleAny struct{}

func (this *TestEventActionHandleAny) Handlelll(data string) {
    testEventRes["TestEventActionHandleAny"] = data
}

func Test_Action_Any(t *testing.T) {
    eq := assertDeepEqualT(t)

    {
        action := NewAction()
        action.Listen("Test_Action_Any", []any{
            &TestEventActionHandleAny{},
            "Handlelll",
        }, DefaultSort)

        init := "init8 => "
        action.Trigger("Test_Action_Any", init)

        eq(testEventRes["TestEventActionHandleAny"], "init8 => ", "Test_Action_Any")
    }

    {
        testEventRes["TestEventActionHandleAny"] = ""

        action := NewAction()
        action.Listen("Test_Action_Any", []any{
            reflect.ValueOf(&TestEventActionHandleAny{}),
            "Handlelll",
        }, DefaultSort)

        init := "init9 => "
        action.Trigger("Test_Action_Any", init)

        eq(testEventRes["TestEventActionHandleAny"], "init9 => ", "Test_Action_Any 2")
    }
}

func testFilterAnyFunc(data string) string {
    return "run " + data
}

func Test_FilterFunc_Any(t *testing.T) {
    eq := assertDeepEqualT(t)

    {
        filter := NewFilter()
        filter.Listen("Test_Filter_Any", []any{
            testFilterAnyFunc,
        }, DefaultSort)

        init := "init6 => "
        res := filter.Trigger("Test_Filter_Any", init)

        eq(res, "run init6 => ", "Test_Filter_Any")
    }

    {
        filter := NewFilter()
        filter.Listen("Test_Filter_Any", []any{
            reflect.ValueOf(testFilterAnyFunc),
        }, DefaultSort)

        init := "init7 => "
        res := filter.Trigger("Test_Filter_Any", init)

        eq(res, "run init7 => ", "Test_Filter_Any 2")
    }
}

func testActionAnyFunc(val string) {
    testEventRes["testActionAnyFunc"] = val
}

func Test_ActionFunc_Any(t *testing.T) {
    eq := assertDeepEqualT(t)

    {
        action := NewAction()
        action.Listen("Test_Action_Any", []any{
            testActionAnyFunc,
        }, DefaultSort)

        init := "init8 => "
        action.Trigger("Test_Action_Any", init)

        eq(testEventRes["testActionAnyFunc"], "init8 => ", "Test_Action_Any")
    }

    {
        testEventRes["testActionAnyFunc"] = ""

        action := NewAction()
        action.Listen("Test_Action_Any", []any{
            reflect.ValueOf(testActionAnyFunc),
        }, DefaultSort)

        init := "init9 => "
        action.Trigger("Test_Action_Any", init)

        eq(testEventRes["testActionAnyFunc"], "init9 => ", "Test_Action_Any 2")
    }
}

func Test_Struct_fail_3(t *testing.T) {
    eq := assertDeepEqualT(t)

    defer func() {
        if e := recover(); e != nil {
            err := fmt.Sprintf("%v", e)

            check := "go-events: call slice func error"
            eq(err, check, "Struct failed 3")
        }
    }()

    action := NewAction()
    action.Listen("Test_Struct_fail_3", []any{}, DefaultSort)

    data1 := "init6"
    action.Trigger("Test_Struct_fail_3", data1)
}

func Test_Struct_fail_33(t *testing.T) {
    eq := assertDeepEqualT(t)

    defer func() {
        if e := recover(); e != nil {
            err := fmt.Sprintf("%v", e)

            check := "go-events: call func type error"
            eq(err, check, "Struct failed 32")
        }
    }()

    action := NewAction()
    action.Listen("Test_Struct_fail_32", []any{
        &TestEventActionHandleAny{},
        123,
    }, DefaultSort)

    data1 := "init6"
    action.Trigger("Test_Struct_fail_32", data1)
}

func Test_Struct_fail_5(t *testing.T) {
    eq := assertDeepEqualT(t)

    defer func() {
        if e := recover(); e != nil {
            err := fmt.Sprintf("%v", e)

            check := "go-events: call func type error"
            eq(err, check, "Struct failed 5")
        }
    }()

    action := NewAction()
    action.Listen("Test_Struct_fail_5", []any{
        &TestEventActionHandleAny{},
        "Test",
    }, DefaultSort)

    data1 := "init6"
    action.Trigger("Test_Struct_fail_5", data1)
}

