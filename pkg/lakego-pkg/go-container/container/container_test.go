package container

import (
    "testing"
)

type ItestBind interface {
    Data() string
}

type testBind struct {}

func (t *testBind) Data() string {
    return "testBind data"
}

type testBind22 struct {}

func (t *testBind22) Data() string {
    return "testBind22 data"
}

type testBind33 struct {}

func (t testBind33) Data() string {
    return "testBind33 data"
}

type testBind2 struct {
    data string
}

func (t *testBind2) Set(data string) {
    t.data = data
}

func (t *testBind2) Get() string {
    return t.data
}

func Test_Bind(t *testing.T) {
    eq := assertDeepEqualT(t)

    di := DI()
    di.Bind("testBind", func() *testBind {
        return &testBind{}
    })
    tb := di.Get("testBind")

    tb2, ok := tb.(*testBind)
    if !ok {
        t.Error("testBind get fail")
    }

    eq(tb2.Data(), "testBind data", "Test_Bind")
}

func Test_BindStruct(t *testing.T) {
    eq := assertDeepEqualT(t)

    di := DI()
    di.Bind(testBind{}, func() *testBind {
        return &testBind{}
    })
    tb := di.Get(testBind{})

    tb2, ok := tb.(*testBind)
    if !ok {
        t.Error("testBind get fail")
    }

    eq(tb2.Data(), "testBind data", "Test_BindStruct")
}

func Test_BindStruct2(t *testing.T) {
    eq := assertDeepEqualT(t)

    di := DI()
    di.Bind(testBind33{}, func() testBind33 {
        return testBind33{}
    })
    tb := di.Get(testBind33{})

    tb2, ok := tb.(testBind33)
    if !ok {
        t.Error("testBind33 get fail")
    }

    eq(tb2.Data(), "testBind33 data", "Test_BindStruct2")
}

func Test_BindStructPtr(t *testing.T) {
    eq := assertDeepEqualT(t)

    di := DI()
    di.Bind(&testBind{}, func() *testBind {
        return &testBind{}
    })
    tb := di.Get(&testBind{})

    tb2, ok := tb.(*testBind)
    if !ok {
        t.Error("testBind get fail")
    }

    eq(tb2.Data(), "testBind data", "Test_BindStructPtr")
}

type testSingleton struct {
    data string
}

func (t *testSingleton) Set(data string) {
    t.data = data
}

func (t *testSingleton) Get() string {
    return t.data
}

func Test_Singleton(t *testing.T) {
    eq := assertDeepEqualT(t)

    di := DI()
    di.Singleton("testSingleton", func() *testSingleton {
        return &testSingleton{}
    })
    tb := di.Get("testSingleton")

    tb2, ok := tb.(*testSingleton)
    if !ok {
        t.Error("testSingleton get fail")
    }

    eq(tb2.Get(), "", "Test_Singleton")

    tb2.Set("222222222")
    eq(tb2.Get(), "222222222", "Test_Singleton")

    tb3 := di.Get("testSingleton")
    tb33, ok := tb3.(*testSingleton)
    if !ok {
        t.Error("testSingleton get fail")
    }

    eq(tb33.Get(), "222222222", "Test_Singleton")
}

func Test_Bind2(t *testing.T) {
    eq := assertDeepEqualT(t)

    di := DI()
    di.Bind("testBind22222", func() *testSingleton {
        ss := &testSingleton{}
        ss.Set("111111111")
        return ss
    })
    tb := di.Get("testBind22222")

    tb2, ok := tb.(*testSingleton)
    if !ok {
        t.Error("testBind22222 get fail")
    }

    eq(tb2.Get(), "111111111", "Test_Bind2")

    tb2.Set("222222222")
    eq(tb2.Get(), "222222222", "Test_Bind2")

    tb3 := di.Get("testBind22222")
    tb33, ok := tb3.(*testSingleton)
    if !ok {
        t.Error("testBind22222 get fail")
    }

    eq(tb33.Get(), "111111111", "Test_Bind2")
}

func Test_BindWithShared(t *testing.T) {
    eq := assertDeepEqualT(t)

    di := DI()
    di.BindWithShared("testSingleton2", func() *testSingleton {
        return &testSingleton{}
    }, true)
    tb := di.Get("testSingleton2")

    tb2, ok := tb.(*testSingleton)
    if !ok {
        t.Error("testSingleton get fail")
    }

    eq(tb2.Get(), "", "BindWithShared")

    tb2.Set("22222222233")
    eq(tb2.Get(), "22222222233", "BindWithShared")

    tb3 := di.Get("testSingleton2")
    tb33, ok := tb3.(*testSingleton)
    if !ok {
        t.Error("testSingleton get fail")
    }

    eq(tb33.Get(), "22222222233", "BindWithShared")
}

func Test_BindStructPtrAndDep(t *testing.T) {
    eq := assertDeepEqualT(t)

    di := NewContainer()
    di.Bind(&testBind{}, func() *testBind {
        return &testBind{}
    })

    di.Bind(&testBind2{}, func(bind *testBind) *testBind2 {
        bb := &testBind2{}
        bb.Set(bind.Data())

        return bb
    })

    tb := di.Get(&testBind2{})

    tb2, ok := tb.(*testBind2)
    if !ok {
        t.Error("testBind get fail")
    }

    eq(tb2.Get(), "testBind data", "Test_BindStructPtrAndDep")
}

func testFunc(in string, bind *testBind) string {
    return "in: " + in + " => bind data: " + bind.Data()
}

func Test_CallFunc(t *testing.T) {
    eq := assertDeepEqualT(t)

    di := NewContainer()
    di.Bind(&testBind{}, func() *testBind {
        return &testBind{}
    })

    res := di.Call(testFunc, []any{"test222"})

    eq(res, "in: test222 => bind data: testBind data", "Test_CallFunc")
}

func testFunc2(in *testBind22, bind *testBind) string {
    return "in: " + in.Data() + " => bind data: " + bind.Data()
}

func Test_CallFunc2(t *testing.T) {
    eq := assertDeepEqualT(t)

    di := NewContainer()
    di.Bind(&testBind{}, func() *testBind {
        return &testBind{}
    })

    res := di.Call(testFunc2, []any{
        &testBind22{},
    })

    eq(res, "in: testBind22 data => bind data: testBind data", "Test_CallFunc2")
}

func testFunc3(bind *testBind, in *testBind22) string {
    return "in1: " + in.Data() + " => bind data: " + bind.Data()
}

func Test_CallFunc3(t *testing.T) {
    eq := assertDeepEqualT(t)

    di := NewContainer()
    di.Bind(&testBind{}, func() *testBind {
        return &testBind{}
    })

    res := di.Call(testFunc3, []any{
        &testBind22{},
    })

    eq(res, "in1: testBind22 data => bind data: testBind data", "Test_CallFunc3")
}

func testFunc33(in *testBind2, bind *testBind2) string {
    return "in33: " + in.Get() + " => bind data: " + bind.Get()
}

func Test_CallFunc33(t *testing.T) {
    eq := assertDeepEqualT(t)

    di := NewContainer()
    di.Bind(&testBind2{}, func() *testBind2 {
        bb := &testBind2{}
        bb.Set("Binding")

        return bb
    })

    bb2 := &testBind2{}
    bb2.Set("args")
    res := di.Call(testFunc33, []any{
        bb2,
    })

    eq(res, "in33: args => bind data: Binding", "Test_CallFunc3")
}

func testInvokeFunc(bind *testBind) string {
    return " => bind data: " + bind.Data()
}

func Test_Invoke(t *testing.T) {
    eq := assertDeepEqualT(t)

    di := NewContainer()
    di.Bind(&testBind{}, func() *testBind {
        return &testBind{}
    })

    res := di.Invoke(testInvokeFunc)

    eq(res, " => bind data: testBind data", "Test_Invoke")
}

func Test_ResolvingAndBind(t *testing.T) {
    eq := assertDeepEqualT(t)

    var nowdata any

    di := NewContainer()
    di.Bind("testBind", func() *testBind {
        return &testBind{}
    })
    di.Resolving("testBind", func(data any, con *Container) {
        nowdata = data
    })
    tb := di.Get("testBind")

    tb2, ok := tb.(*testBind)
    if !ok {
        t.Error("testBind get fail")
    }

    eq(tb2.Data(), "testBind data", "Test_ResolvingAndBind")
    eq(getStructName(nowdata), "*github.com/deatil/go-container/container.testBind", "Test_ResolvingAndBind nowdata")
}

func Test_Make(t *testing.T) {
    eq := assertDeepEqualT(t)

    di := NewContainer()
    di.Bind(&testBind{}, func() *testBind {
        return &testBind{}
    })

    di.Bind(&testBind2{}, func(data string, bind *testBind) *testBind2 {
        bb := &testBind2{}
        bb.Set(bind.Data() + "=>" + data)

        return bb
    })

    tb := di.Make(&testBind2{}, []any{"make data"})

    tb2, ok := tb.(*testBind2)
    if !ok {
        t.Error("testBind get fail")
    }

    eq(tb2.Get(), "testBind data=>make data", "Test_Make")
}

func Test_Instance(t *testing.T) {
    eq := assertDeepEqualT(t)

    bb := &testBind{}

    di := NewContainer()
    di.Instance("bb", bb)

    tb := di.Get("bb")

    tb2, ok := tb.(*testBind)
    if !ok {
        t.Error("testBind get fail")
    }

    eq(tb2.Data(), "testBind data", "Test_Instance")
}

func Test_Has(t *testing.T) {
    eq := assertDeepEqualT(t)

    di := DI()
    di.Bind("testBind", func() *testBind {
        return &testBind{}
    })
    di.Singleton("testBind2", func() *testBind {
        return &testBind{}
    })

    eq(di.Bound("testBind"), true, "Test_Has Bound")
    eq(di.Has("testBind"), true, "Test_Has Has")
    eq(di.Exists("testBind"), false, "Test_Has Exists")
    eq(di.IsShared("testBind"), false, "Test_Has IsShared")
    eq(di.IsShared("testBind2"), true, "Test_Has IsShared 2")

    var _ = di.Get("testBind2")
    eq(di.Exists("testBind2"), true, "Test_Has Exists 2")

    di.Delete("testBind2")
    eq(di.Exists("testBind2"), false, "Test_Has Exists 2")
}

func Test_GetAlias(t *testing.T) {
    eq := assertDeepEqualT(t)

    di := DI()
    di.Bind("testBind", func() *testBind {
        return &testBind{}
    })
    di.Bind("testBind333", "testBind")

    res := di.GetAlias("testBind333")

    eq(res, "testBind", "Test_GetAlias")
}

func Test_Provide(t *testing.T) {
    eq := assertDeepEqualT(t)

    di := New()
    di.Provide(func() *testBind {
        return &testBind{}
    })
    di.Invoke(func(tb *testBind) {
        eq(tb.Data(), "testBind data", "Test_Provide")
    })
}

func Test_ifUseInterface(t *testing.T) {
    eq := assertDeepEqualT(t)

    tt := &testBind{}

    res := ifInterface[ItestBind](tt)

    eq(res, true, "Test_ifUseInterface")
}

func Test_ifUseInterface2(t *testing.T) {
    eq := assertDeepEqualT(t)

    tt := testBind33{}

    res := ifInterface[ItestBind](tt)

    eq(res, true, "Test_ifUseInterface2")
}

func Test_Provide2(t *testing.T) {
    eq := assertDeepEqualT(t)

    di := New()
    di.Provide(func() *testBind {
        return &testBind{}
    })
    di.Invoke(func(tb ItestBind) {
        eq(tb.Data(), "testBind data", "Test_Provide2")
    })
}

func Test_Provide3(t *testing.T) {
    eq := assertDeepEqualT(t)

    di := New()
    di.Provide(func() ItestBind {
        return &testBind{}
    })
    di.Invoke(func(tb ItestBind) {
        eq(tb.Data(), "testBind data", "Test_Provide3")
    })
}

func Test_Provide33(t *testing.T) {
    eq := assertDeepEqualT(t)

    di := New()
    di.Provide(func() testBind33 {
        return testBind33{}
    })
    di.Invoke(func(tb ItestBind) {
        eq(tb.Data(), "testBind33 data", "Test_Provide33")
    })
}

func Test_UseContainer(t *testing.T) {
    eq := assertDeepEqualT(t)

    di := New()
    di.Provide(func() testBind33 {
        return testBind33{}
    })
    di.Bind("testBind", func() *testBind {
        return &testBind{}
    })
    di.Invoke(func(con *Container, tb ItestBind) {
        tb1 := con.Get("testBind")
        tb2, ok := tb1.(*testBind)
        if !ok {
            t.Error("testBind get fail")
        }

        eq(tb2.Data(), "testBind data", "Test_UseContainer")

        eq(tb.Data(), "testBind33 data", "Test_UseContainer")
    })
}

func Test_CheckLOC(t *testing.T) {
    eq := assertDeepEqualT(t)

    di := NewContainer()
    di.Bind(&testBind2{}, func() *testBind2 {
        bb := &testBind2{}
        bb.Set("Struct Binding")

        return bb
    })
    di.Bind("testBind2", func() *testBind2 {
        bb := &testBind2{}
        bb.Set("UseName")

        return bb
    })
    di.Bind("testBind3", func() *testBind2 {
        bb := &testBind2{}
        bb.Set("UseName3")

        return bb
    })

    di.Invoke(func(con *Container, tb *testBind2) {
        tb1 := con.Get("testBind2")
        tb2, ok := tb1.(*testBind2)
        if !ok {
            t.Error("testBind2 get fail")
        }

        eq(tb2.Get(), "UseName", "Test_CheckLOC")

        eq(tb.Get(), "Struct Binding", "Test_CheckLOC")
    })}

