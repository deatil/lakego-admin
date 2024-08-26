package container

import (
    "testing"
)

type testBind struct {}

func (t *testBind) Data() string {
    return "testBind data"
}

type testBind22 struct {}

func (t *testBind22) Data() string {
    return "testBind22 data"
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
