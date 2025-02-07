package test

import (
    "io"
    "os"
    "fmt"
    "time"
    "math"
    "errors"
    "regexp"
    "reflect"
    "testing"
    "runtime"
    "strings"
    "path/filepath"
)

var (
    i     interface{}
    zeros = []interface{}{
        false,
        byte(0),
        complex64(0),
        complex128(0),
        float32(0),
        float64(0),
        int(0),
        int8(0),
        int16(0),
        int32(0),
        int64(0),
        rune(0),
        uint(0),
        uint8(0),
        uint16(0),
        uint32(0),
        uint64(0),
        uintptr(0),
        "",
        [0]interface{}{},
        []interface{}(nil),
        struct{ x int }{},
        (*interface{})(nil),
        (func())(nil),
        nil,
        interface{}(nil),
        map[interface{}]interface{}(nil),
        (chan interface{})(nil),
        (<-chan interface{})(nil),
        (chan<- interface{})(nil),
    }
    nonZeros = []interface{}{
        true,
        byte(1),
        complex64(1),
        complex128(1),
        float32(1),
        float64(1),
        int(1),
        int8(1),
        int16(1),
        int32(1),
        int64(1),
        rune(1),
        uint(1),
        uint8(1),
        uint16(1),
        uint32(1),
        uint64(1),
        uintptr(1),
        "s",
        [1]interface{}{1},
        []interface{}{},
        struct{ x int }{1},
        (&i),
        (func() {}),
        interface{}(1),
        map[interface{}]interface{}{},
        (make(chan interface{})),
        (<-chan interface{})(make(chan interface{})),
        (chan<- interface{})(make(chan interface{})),
    }
)

// AssertionTesterConformingObject is an object that conforms to the AssertionTesterInterface interface
type AssertionTesterConformingObject struct {
}

func (a *AssertionTesterConformingObject) TestMethod() {
}

// AssertionTesterNonConformingObject is an object that does not conform to the AssertionTesterInterface interface
type AssertionTesterNonConformingObject struct {
}

func Test_ObjectsAreEqual(t *testing.T) {
    cases := []struct {
        expected interface{}
        actual   interface{}
        result   bool
    }{
        // cases that are expected to be equal
        {"Hello World", "Hello World", true},
        {123, 123, true},
        {123.5, 123.5, true},
        {[]byte("Hello World"), []byte("Hello World"), true},
        {nil, nil, true},

        // cases that are expected not to be equal
        {map[int]int{5: 10}, map[int]int{10: 20}, false},
        {'x', "x", false},
        {"x", 'x', false},
        {0, 0.1, false},
        {0.1, 0, false},
        {time.Now, time.Now, false},
        {func() {}, func() {}, false},
        {uint32(10), int32(10), false},
    }

    for _, c := range cases {
        t.Run(fmt.Sprintf("ObjectsAreEqual(%#v, %#v)", c.expected, c.actual), func(t *testing.T) {
            res := ObjectsAreEqual(c.expected, c.actual)

            if res != c.result {
                t.Errorf("ObjectsAreEqual(%#v, %#v) should return %#v", c.expected, c.actual, c.result)
            }

        })
    }
}

func Test_ObjectsAreEqualValues(t *testing.T) {
    now := time.Now()

    cases := []struct {
        expected interface{}
        actual   interface{}
        result   bool
    }{
        {uint32(10), int32(10), true},
        {0, nil, false},
        {nil, 0, false},
        {now, now.In(time.Local), false}, // should not be time zone independent
        {int(270), int8(14), false},      // should handle overflow/underflow
        {int8(14), int(270), false},
        {[]int{270, 270}, []int8{14, 14}, false},
        {complex128(1e+100 + 1e+100i), complex64(complex(math.Inf(0), math.Inf(0))), false},
        {complex64(complex(math.Inf(0), math.Inf(0))), complex128(1e+100 + 1e+100i), false},
        {complex128(1e+100 + 1e+100i), 270, false},
        {270, complex128(1e+100 + 1e+100i), false},
        {complex128(1e+100 + 1e+100i), 3.14, false},
        {3.14, complex128(1e+100 + 1e+100i), false},
        {complex128(1e+10 + 1e+10i), complex64(1e+10 + 1e+10i), true},
        {complex64(1e+10 + 1e+10i), complex128(1e+10 + 1e+10i), true},
    }

    for _, c := range cases {
        t.Run(fmt.Sprintf("ObjectsAreEqualValues(%#v, %#v)", c.expected, c.actual), func(t *testing.T) {
            res := ObjectsAreEqualValues(c.expected, c.actual)

            if res != c.result {
                t.Errorf("ObjectsAreEqualValues(%#v, %#v) should return %#v", c.expected, c.actual, c.result)
            }
        })
    }
}

type Nested struct {
    Exported    interface{}
    notExported interface{}
}

type S struct {
    Exported1    interface{}
    Exported2    Nested
    notExported1 interface{}
    notExported2 Nested
}

type S2 struct {
    foo interface{}
}

type S3 struct {
    Exported1 *Nested
    Exported2 *Nested
}

type S4 struct {
    Exported1 []*Nested
}

type S5 struct {
    Exported Nested
}

type S6 struct {
    Exported   string
    unexported string
}

func Test_ObjectsExportedFieldsAreEqual(t *testing.T) {

    intValue := 1

    cases := []struct {
        expected interface{}
        actual   interface{}
        result   bool
    }{
        {S{1, Nested{2, 3}, 4, Nested{5, 6}}, S{1, Nested{2, 3}, 4, Nested{5, 6}}, true},
        {S{1, Nested{2, 3}, 4, Nested{5, 6}}, S{1, Nested{2, 3}, "a", Nested{5, 6}}, true},
        {S{1, Nested{2, 3}, 4, Nested{5, 6}}, S{1, Nested{2, 3}, 4, Nested{5, "a"}}, true},
        {S{1, Nested{2, 3}, 4, Nested{5, 6}}, S{1, Nested{2, 3}, 4, Nested{"a", "a"}}, true},
        {S{1, Nested{2, 3}, 4, Nested{5, 6}}, S{1, Nested{2, "a"}, 4, Nested{5, 6}}, true},
        {S{1, Nested{2, 3}, 4, Nested{5, 6}}, S{"a", Nested{2, 3}, 4, Nested{5, 6}}, false},
        {S{1, Nested{2, 3}, 4, Nested{5, 6}}, S{1, Nested{"a", 3}, 4, Nested{5, 6}}, false},
        {S{1, Nested{2, 3}, 4, Nested{5, 6}}, S2{1}, false},
        {1, S{1, Nested{2, 3}, 4, Nested{5, 6}}, false},

        {S3{&Nested{1, 2}, &Nested{3, 4}}, S3{&Nested{1, 2}, &Nested{3, 4}}, true},
        {S3{nil, &Nested{3, 4}}, S3{nil, &Nested{3, 4}}, true},
        {S3{&Nested{1, 2}, &Nested{3, 4}}, S3{&Nested{1, 2}, &Nested{3, "b"}}, true},
        {S3{&Nested{1, 2}, &Nested{3, 4}}, S3{&Nested{1, "a"}, &Nested{3, "b"}}, true},
        {S3{&Nested{1, 2}, &Nested{3, 4}}, S3{&Nested{"a", 2}, &Nested{3, 4}}, false},
        {S3{&Nested{1, 2}, &Nested{3, 4}}, S3{}, false},
        {S3{}, S3{}, true},

        {S4{[]*Nested{{1, 2}}}, S4{[]*Nested{{1, 2}}}, true},
        {S4{[]*Nested{{1, 2}}}, S4{[]*Nested{{1, 3}}}, true},
        {S4{[]*Nested{{1, 2}, {3, 4}}}, S4{[]*Nested{{1, "a"}, {3, "b"}}}, true},
        {S4{[]*Nested{{1, 2}, {3, 4}}}, S4{[]*Nested{{1, "a"}, {2, "b"}}}, false},

        {Nested{&intValue, 2}, Nested{&intValue, 2}, true},
        {Nested{&Nested{1, 2}, 3}, Nested{&Nested{1, "b"}, 3}, true},
        {Nested{&Nested{1, 2}, 3}, Nested{nil, 3}, false},

        {
            Nested{map[interface{}]*Nested{nil: nil}, 2},
            Nested{map[interface{}]*Nested{nil: nil}, 2},
            true,
        },
        {
            Nested{map[interface{}]*Nested{"a": nil}, 2},
            Nested{map[interface{}]*Nested{"a": nil}, 2},
            true,
        },
        {
            Nested{map[interface{}]*Nested{"a": nil}, 2},
            Nested{map[interface{}]*Nested{"a": {1, 2}}, 2},
            false,
        },
        {
            Nested{map[interface{}]Nested{"a": {1, 2}, "b": {3, 4}}, 2},
            Nested{map[interface{}]Nested{"a": {1, 5}, "b": {3, 7}}, 2},
            true,
        },
        {
            Nested{map[interface{}]Nested{"a": {1, 2}, "b": {3, 4}}, 2},
            Nested{map[interface{}]Nested{"a": {2, 2}, "b": {3, 4}}, 2},
            false,
        },
    }

    for _, c := range cases {
        t.Run(fmt.Sprintf("ObjectsExportedFieldsAreEqual(%#v, %#v)", c.expected, c.actual), func(t *testing.T) {
            res := ObjectsExportedFieldsAreEqual(c.expected, c.actual)

            if res != c.result {
                t.Errorf("ObjectsExportedFieldsAreEqual(%#v, %#v) should return %#v", c.expected, c.actual, c.result)
            }

        })
    }
}

func Test_CopyExportedFields(t *testing.T) {
    intValue := 1

    cases := []struct {
        input    interface{}
        expected interface{}
    }{
        {
            input:    Nested{"a", "b"},
            expected: Nested{"a", nil},
        },
        {
            input:    Nested{&intValue, 2},
            expected: Nested{&intValue, nil},
        },
        {
            input:    Nested{nil, 3},
            expected: Nested{nil, nil},
        },
        {
            input:    S{1, Nested{2, 3}, 4, Nested{5, 6}},
            expected: S{1, Nested{2, nil}, nil, Nested{}},
        },
        {
            input:    S3{},
            expected: S3{},
        },
        {
            input:    S3{&Nested{1, 2}, &Nested{3, 4}},
            expected: S3{&Nested{1, nil}, &Nested{3, nil}},
        },
        {
            input:    S3{Exported1: &Nested{"a", "b"}},
            expected: S3{Exported1: &Nested{"a", nil}},
        },
        {
            input: S4{[]*Nested{
                nil,
                {1, 2},
            }},
            expected: S4{[]*Nested{
                nil,
                {1, nil},
            }},
        },
        {
            input: S4{[]*Nested{
                {1, 2}},
            },
            expected: S4{[]*Nested{
                {1, nil}},
            },
        },
        {
            input: S4{[]*Nested{
                {1, 2},
                {3, 4},
            }},
            expected: S4{[]*Nested{
                {1, nil},
                {3, nil},
            }},
        },
        {
            input:    S5{Exported: Nested{"a", "b"}},
            expected: S5{Exported: Nested{"a", nil}},
        },
        {
            input:    S6{"a", "b"},
            expected: S6{"a", ""},
        },
    }

    for _, c := range cases {
        t.Run("", func(t *testing.T) {
            output := copyExportedFields(c.input)
            if !ObjectsAreEqualValues(c.expected, output) {
                t.Errorf("%#v, %#v should be equal", c.expected, output)
            }
        })
    }
}

func Test_IsType(t *testing.T) {
    mockT := new(testing.T)

    if !IsType(mockT, new(AssertionTesterConformingObject), new(AssertionTesterConformingObject)) {
        t.Error("IsType should return true: AssertionTesterConformingObject is the same type as AssertionTesterConformingObject")
    }

    if IsType(mockT, new(AssertionTesterConformingObject), new(AssertionTesterNonConformingObject)) {
        t.Error("IsType should return false: AssertionTesterConformingObject is not the same type as AssertionTesterNonConformingObject")
    }
}

func Test_Exactly(t *testing.T) {

    mockT := new(testing.T)

    a := float32(1)
    b := float64(1)
    c := float32(1)
    d := float32(2)
    cases := []struct {
        expected interface{}
        actual   interface{}
        result   bool
    }{
        {a, b, false},
        {a, d, false},
        {a, c, true},
        {nil, a, false},
        {a, nil, false},
    }

    for _, c := range cases {
        t.Run(fmt.Sprintf("Exactly(%#v, %#v)", c.expected, c.actual), func(t *testing.T) {
            res := Exactly(mockT, c.expected, c.actual)

            if res != c.result {
                t.Errorf("Exactly(%#v, %#v) should return %#v", c.expected, c.actual, c.result)
            }
        })
    }
}

func Test_Equal(t *testing.T) {
    type myType string

    mockT := new(testing.T)
    var m map[string]interface{}

    cases := []struct {
        expected interface{}
        actual   interface{}
        result   bool
        remark   string
    }{
        {"Hello World", "Hello World", true, ""},
        {123, 123, true, ""},
        {123.5, 123.5, true, ""},
        {[]byte("Hello World"), []byte("Hello World"), true, ""},
        {nil, nil, true, ""},
        {int32(123), int32(123), true, ""},
        {uint64(123), uint64(123), true, ""},
        {myType("1"), myType("1"), true, ""},
        {&struct{}{}, &struct{}{}, true, "pointer equality is based on equality of underlying value"},

        // Not expected to be equal
        {m["bar"], "something", false, ""},
        {myType("1"), myType("2"), false, ""},

        // A case that might be confusing, especially with numeric literals
        {10, uint(10), false, ""},
    }

    for _, c := range cases {
        t.Run(fmt.Sprintf("Equal(%#v, %#v)", c.expected, c.actual), func(t *testing.T) {
            res := Equal(mockT, c.expected, c.actual)

            if res != c.result {
                t.Errorf("Equal(%#v, %#v) should return %#v: %s", c.expected, c.actual, c.result, c.remark)
            }
        })
    }
}

func Test_NotEqual(t *testing.T) {

    mockT := new(testing.T)

    cases := []struct {
        expected interface{}
        actual   interface{}
        result   bool
    }{
        // cases that are expected not to match
        {"Hello World", "Hello World!", true},
        {123, 1234, true},
        {123.5, 123.55, true},
        {[]byte("Hello World"), []byte("Hello World!"), true},
        {nil, new(AssertionTesterConformingObject), true},

        // cases that are expected to match
        {nil, nil, false},
        {"Hello World", "Hello World", false},
        {123, 123, false},
        {123.5, 123.5, false},
        {[]byte("Hello World"), []byte("Hello World"), false},
        {new(AssertionTesterConformingObject), new(AssertionTesterConformingObject), false},
        {&struct{}{}, &struct{}{}, false},
        {func() int { return 23 }, func() int { return 24 }, false},
        // A case that might be confusing, especially with numeric literals
        {int(10), uint(10), true},
    }

    for _, c := range cases {
        t.Run(fmt.Sprintf("NotEqual(%#v, %#v)", c.expected, c.actual), func(t *testing.T) {
            res := NotEqual(mockT, c.expected, c.actual)

            if res != c.result {
                t.Errorf("NotEqual(%#v, %#v) should return %#v", c.expected, c.actual, c.result)
            }
        })
    }
}

func Test_NotEqualValues(t *testing.T) {
    mockT := new(testing.T)

    cases := []struct {
        expected interface{}
        actual   interface{}
        result   bool
    }{
        // cases that are expected not to match
        {"Hello World", "Hello World!", true},
        {123, 1234, true},
        {123.5, 123.55, true},
        {[]byte("Hello World"), []byte("Hello World!"), true},
        {nil, new(AssertionTesterConformingObject), true},

        // cases that are expected to match
        {nil, nil, false},
        {"Hello World", "Hello World", false},
        {123, 123, false},
        {123.5, 123.5, false},
        {[]byte("Hello World"), []byte("Hello World"), false},
        {new(AssertionTesterConformingObject), new(AssertionTesterConformingObject), false},
        {&struct{}{}, &struct{}{}, false},

        // Different behavior from NotEqual()
        {func() int { return 23 }, func() int { return 24 }, true},
        {int(10), int(11), true},
        {int(10), uint(10), false},

        {struct{}{}, struct{}{}, false},
    }

    for _, c := range cases {
        t.Run(fmt.Sprintf("NotEqualValues(%#v, %#v)", c.expected, c.actual), func(t *testing.T) {
            res := NotEqualValues(mockT, c.expected, c.actual)

            if res != c.result {
                t.Errorf("NotEqualValues(%#v, %#v) should return %#v", c.expected, c.actual, c.result)
            }
        })
    }
}

func ptr(i int) *int {
    return &i
}

func Test_Same(t *testing.T) {
    mockT := new(testing.T)

    if Same(mockT, ptr(1), ptr(1)) {
        t.Error("Same should return false")
    }
    if Same(mockT, 1, 1) {
        t.Error("Same should return false")
    }
    p := ptr(2)
    if Same(mockT, p, *p) {
        t.Error("Same should return false")
    }
    if !Same(mockT, p, p) {
        t.Error("Same should return true")
    }
}

func Test_NotSame(t *testing.T) {
    mockT := new(testing.T)

    if !NotSame(mockT, ptr(1), ptr(1)) {
        t.Error("NotSame should return true; different pointers")
    }
    if !NotSame(mockT, 1, 1) {
        t.Error("NotSame should return true; constant inputs")
    }
    p := ptr(2)
    if !NotSame(mockT, p, *p) {
        t.Error("NotSame should return true; mixed-type inputs")
    }
    if NotSame(mockT, p, p) {
        t.Error("NotSame should return false")
    }
}

func Test_samePointers(t *testing.T) {
    p := ptr(2)

    type args struct {
        first  interface{}
        second interface{}
    }
    tests := []struct {
        name string
        args args
        same BoolAssertionFunc
        ok   BoolAssertionFunc
    }{
        {
            name: "1 != 2",
            args: args{first: 1, second: 2},
            same: False,
            ok:   False,
        },
        {
            name: "1 != 1 (not same ptr)",
            args: args{first: 1, second: 1},
            same: False,
            ok:   False,
        },
        {
            name: "ptr(1) == ptr(1)",
            args: args{first: p, second: p},
            same: True,
            ok:   True,
        },
        {
            name: "int(1) != float32(1)",
            args: args{first: int(1), second: float32(1)},
            same: False,
            ok:   False,
        },
        {
            name: "array != slice",
            args: args{first: [2]int{1, 2}, second: []int{1, 2}},
            same: False,
            ok:   False,
        },
        {
            name: "non-pointer vs pointer (1 != ptr(2))",
            args: args{first: 1, second: p},
            same: False,
            ok:   False,
        },
        {
            name: "pointer vs non-pointer (ptr(2) != 1)",
            args: args{first: p, second: 1},
            same: False,
            ok:   False,
        },
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            same, ok := samePointers(tt.args.first, tt.args.second)
            tt.same(t, same)
            tt.ok(t, ok)
        })
    }
}

func Test_NotNil(t *testing.T) {
    mockT := new(testing.T)

    if !NotNil(mockT, new(AssertionTesterConformingObject)) {
        t.Error("NotNil should return true: object is not nil")
    }
    if NotNil(mockT, nil) {
        t.Error("NotNil should return false: object is nil")
    }
    if NotNil(mockT, (*struct{})(nil)) {
        t.Error("NotNil should return false: object is (*struct{})(nil)")
    }

}

func Test_Nil(t *testing.T) {

    mockT := new(testing.T)

    if !Nil(mockT, nil) {
        t.Error("Nil should return true: object is nil")
    }
    if !Nil(mockT, (*struct{})(nil)) {
        t.Error("Nil should return true: object is (*struct{})(nil)")
    }
    if Nil(mockT, new(AssertionTesterConformingObject)) {
        t.Error("Nil should return false: object is not nil")
    }

}

func Test_Len(t *testing.T) {
    mockT := new(testing.T)

    False(t, Len(mockT, nil, 0), "nil does not have length")
    False(t, Len(mockT, 0, 0), "int does not have length")
    False(t, Len(mockT, true, 0), "true does not have length")
    False(t, Len(mockT, false, 0), "false does not have length")
    False(t, Len(mockT, 'A', 0), "Rune does not have length")
    False(t, Len(mockT, struct{}{}, 0), "Struct does not have length")

    ch := make(chan int, 5)
    ch <- 1
    ch <- 2
    ch <- 3

    cases := []struct {
        v               interface{}
        l               int
        expected1234567 string // message when expecting 1234567 items
    }{
        {[]int{1, 2, 3}, 3, `"[1 2 3]" should have 1234567 item(s), but has 3`},
        {[...]int{1, 2, 3}, 3, `"[1 2 3]" should have 1234567 item(s), but has 3`},
        {"ABC", 3, `"ABC" should have 1234567 item(s), but has 3`},
        {map[int]int{1: 2, 2: 4, 3: 6}, 3, `"map[1:2 2:4 3:6]" should have 1234567 item(s), but has 3`},
        {ch, 3, ""},

        {[]int{}, 0, `"[]" should have 1234567 item(s), but has 0`},
        {map[int]int{}, 0, `"map[]" should have 1234567 item(s), but has 0`},
        {make(chan int), 0, ""},

        {[]int(nil), 0, `"[]" should have 1234567 item(s), but has 0`},
        {map[int]int(nil), 0, `"map[]" should have 1234567 item(s), but has 0`},
        {(chan int)(nil), 0, `"<nil>" should have 1234567 item(s), but has 0`},
    }

    for _, c := range cases {
        True(t, Len(mockT, c.v, c.l), "%#v have %d items", c.v, c.l)
        False(t, Len(mockT, c.v, c.l+1), "%#v have %d items", c.v, c.l)
        if c.expected1234567 != "" {
            msgMock := new(mockTestingT)
            Len(msgMock, c.v, 1234567)
            Contains(t, msgMock.errorString(), c.expected1234567)
        }
    }
}

func Test_True(t *testing.T) {

    mockT := new(testing.T)

    if !True(mockT, true) {
        t.Error("True should return true")
    }
    if True(mockT, false) {
        t.Error("True should return false")
    }

}

func Test_False(t *testing.T) {

    mockT := new(testing.T)

    if !False(mockT, false) {
        t.Error("False should return true")
    }
    if False(mockT, true) {
        t.Error("False should return false")
    }

}

func Test_isEmpty(t *testing.T) {

    chWithValue := make(chan struct{}, 1)
    chWithValue <- struct{}{}

    True(t, isEmpty(""))
    True(t, isEmpty(nil))
    True(t, isEmpty([]string{}))
    True(t, isEmpty(0))
    True(t, isEmpty(int32(0)))
    True(t, isEmpty(int64(0)))
    True(t, isEmpty(false))
    True(t, isEmpty(map[string]string{}))
    True(t, isEmpty(new(time.Time)))
    True(t, isEmpty(time.Time{}))
    True(t, isEmpty(make(chan struct{})))
    True(t, isEmpty([1]int{}))
    False(t, isEmpty("something"))
    False(t, isEmpty(errors.New("something")))
    False(t, isEmpty([]string{"something"}))
    False(t, isEmpty(1))
    False(t, isEmpty(true))
    False(t, isEmpty(map[string]string{"Hello": "World"}))
    False(t, isEmpty(chWithValue))
    False(t, isEmpty([1]int{42}))
}

func Test_Empty(t *testing.T) {

    mockT := new(testing.T)
    chWithValue := make(chan struct{}, 1)
    chWithValue <- struct{}{}
    var tiP *time.Time
    var tiNP time.Time
    var s *string
    var f *os.File
    sP := &s
    x := 1
    xP := &x

    type TString string
    type TStruct struct {
        x int
    }

    True(t, Empty(mockT, ""), "Empty string is empty")
    True(t, Empty(mockT, nil), "Nil is empty")
    True(t, Empty(mockT, []string{}), "Empty string array is empty")
    True(t, Empty(mockT, 0), "Zero int value is empty")
    True(t, Empty(mockT, false), "False value is empty")
    True(t, Empty(mockT, make(chan struct{})), "Channel without values is empty")
    True(t, Empty(mockT, s), "Nil string pointer is empty")
    True(t, Empty(mockT, f), "Nil os.File pointer is empty")
    True(t, Empty(mockT, tiP), "Nil time.Time pointer is empty")
    True(t, Empty(mockT, tiNP), "time.Time is empty")
    True(t, Empty(mockT, TStruct{}), "struct with zero values is empty")
    True(t, Empty(mockT, TString("")), "empty aliased string is empty")
    True(t, Empty(mockT, sP), "ptr to nil value is empty")
    True(t, Empty(mockT, [1]int{}), "array is state")

    False(t, Empty(mockT, "something"), "Non Empty string is not empty")
    False(t, Empty(mockT, errors.New("something")), "Non nil object is not empty")
    False(t, Empty(mockT, []string{"something"}), "Non empty string array is not empty")
    False(t, Empty(mockT, 1), "Non-zero int value is not empty")
    False(t, Empty(mockT, true), "True value is not empty")
    False(t, Empty(mockT, chWithValue), "Channel with values is not empty")
    False(t, Empty(mockT, TStruct{x: 1}), "struct with initialized values is empty")
    False(t, Empty(mockT, TString("abc")), "non-empty aliased string is empty")
    False(t, Empty(mockT, xP), "ptr to non-nil value is not empty")
    False(t, Empty(mockT, [1]int{42}), "array is not state")
}

func Test_NotEmpty(t *testing.T) {

    mockT := new(testing.T)
    chWithValue := make(chan struct{}, 1)
    chWithValue <- struct{}{}

    False(t, NotEmpty(mockT, ""), "Empty string is empty")
    False(t, NotEmpty(mockT, nil), "Nil is empty")
    False(t, NotEmpty(mockT, []string{}), "Empty string array is empty")
    False(t, NotEmpty(mockT, 0), "Zero int value is empty")
    False(t, NotEmpty(mockT, false), "False value is empty")
    False(t, NotEmpty(mockT, make(chan struct{})), "Channel without values is empty")
    False(t, NotEmpty(mockT, [1]int{}), "array is state")

    True(t, NotEmpty(mockT, "something"), "Non Empty string is not empty")
    True(t, NotEmpty(mockT, errors.New("something")), "Non nil object is not empty")
    True(t, NotEmpty(mockT, []string{"something"}), "Non empty string array is not empty")
    True(t, NotEmpty(mockT, 1), "Non-zero int value is not empty")
    True(t, NotEmpty(mockT, true), "True value is not empty")
    True(t, NotEmpty(mockT, chWithValue), "Channel with values is not empty")
    True(t, NotEmpty(mockT, [1]int{42}), "array is not state")
}

func Test_NoError(t *testing.T) {

    mockT := new(testing.T)

    // start with a nil error
    var err error

    True(t, NoError(mockT, err), "NoError should return True for nil arg")

    // now set an error
    err = errors.New("some error")

    False(t, NoError(mockT, err), "NoError with error should return False")

    // returning an empty error interface
    err = func() error {
        var err *customError
        return err
    }()

    if err == nil { // err is not nil here!
        t.Errorf("Error should be nil due to empty interface: %s", err)
    }

    False(t, NoError(mockT, err), "NoError should fail with empty error interface")
}

type customError struct{}

func (*customError) Error() string { return "fail" }

func Test_Error(t *testing.T) {

    mockT := new(testing.T)

    // start with a nil error
    var err error

    False(t, Error(mockT, err), "Error should return False for nil arg")

    // now set an error
    err = errors.New("some error")

    True(t, Error(mockT, err), "Error with error should return True")

    // go vet check
    True(t, Errorf(mockT, err, "example with %s", "formatted message"), "Errorf with error should return True")

    // returning an empty error interface
    err = func() error {
        var err *customError
        return err
    }()

    if err == nil { // err is not nil here!
        t.Errorf("Error should be nil due to empty interface: %s", err)
    }

    True(t, Error(mockT, err), "Error should pass with empty error interface")
}

func Test_EqualError(t *testing.T) {
    mockT := new(testing.T)

    // start with a nil error
    var err error
    False(t, EqualError(mockT, err, ""),
        "EqualError should return false for nil arg")

    // now set an error
    err = errors.New("some error")
    False(t, EqualError(mockT, err, "Not some error"),
        "EqualError should return false for different error string")
    True(t, EqualError(mockT, err, "some error"),
        "EqualError should return true")
}

func Test_ErrorContains(t *testing.T) {
    mockT := new(testing.T)

    // start with a nil error
    var err error
    False(t, ErrorContains(mockT, err, ""),
        "ErrorContains should return false for nil arg")

    // now set an error
    err = errors.New("some error: another error")
    False(t, ErrorContains(mockT, err, "bad error"),
        "ErrorContains should return false for different error string")
    True(t, ErrorContains(mockT, err, "some error"),
        "ErrorContains should return true")
    True(t, ErrorContains(mockT, err, "another error"),
        "ErrorContains should return true")
}

func Test_Condition(t *testing.T) {
    mockT := new(testing.T)

    if !Condition(mockT, func() bool { return true }, "Truth") {
        t.Error("Condition should return true")
    }

    if Condition(mockT, func() bool { return false }, "Lie") {
        t.Error("Condition should return false")
    }

}

func Test_DidPanic(t *testing.T) {

    const panicMsg = "Panic!"

    if funcDidPanic, msg, _ := didPanic(func() {
        panic(panicMsg)
    }); !funcDidPanic || msg != panicMsg {
        t.Error("didPanic should return true, panicMsg")
    }

    if funcDidPanic, msg, _ := didPanic(func() {
        panic(nil)
    }); !funcDidPanic || msg != nil {
        t.Error("didPanic should return true, nil")
    }

    if funcDidPanic, _, _ := didPanic(func() {
    }); funcDidPanic {
        t.Error("didPanic should return false")
    }

}

func Test_Panics(t *testing.T) {

    mockT := new(testing.T)

    if !Panics(mockT, func() {
        panic("Panic!")
    }) {
        t.Error("Panics should return true")
    }

    if Panics(mockT, func() {
    }) {
        t.Error("Panics should return false")
    }

}

func Test_PanicsWithValue(t *testing.T) {

    mockT := new(testing.T)

    if !PanicsWithValue(mockT, "Panic!", func() {
        panic("Panic!")
    }) {
        t.Error("PanicsWithValue should return true")
    }

    if !PanicsWithValue(mockT, nil, func() {
        panic(nil)
    }) {
        t.Error("PanicsWithValue should return true")
    }

    if PanicsWithValue(mockT, "Panic!", func() {
    }) {
        t.Error("PanicsWithValue should return false")
    }

    if PanicsWithValue(mockT, "at the disco", func() {
        panic("Panic!")
    }) {
        t.Error("PanicsWithValue should return false")
    }
}

func Test_PanicsWithError(t *testing.T) {

    mockT := new(testing.T)

    if !PanicsWithError(mockT, "panic", func() {
        panic(errors.New("panic"))
    }) {
        t.Error("PanicsWithError should return true")
    }

    if PanicsWithError(mockT, "Panic!", func() {
    }) {
        t.Error("PanicsWithError should return false")
    }

    if PanicsWithError(mockT, "at the disco", func() {
        panic(errors.New("panic"))
    }) {
        t.Error("PanicsWithError should return false")
    }

    if PanicsWithError(mockT, "Panic!", func() {
        panic("panic")
    }) {
        t.Error("PanicsWithError should return false")
    }
}

func Test_NotPanics(t *testing.T) {

    mockT := new(testing.T)

    if !NotPanics(mockT, func() {
    }) {
        t.Error("NotPanics should return true")
    }

    if NotPanics(mockT, func() {
        panic("Panic!")
    }) {
        t.Error("NotPanics should return false")
    }

}

type mockTestingT struct {
    errorFmt string
    args     []interface{}
}

func (m *mockTestingT) errorString() string {
    return fmt.Sprintf(m.errorFmt, m.args...)
}

func (m *mockTestingT) Errorf(format string, args ...interface{}) {
    m.errorFmt = format
    m.args = args
}

func (m *mockTestingT) Failed() bool {
    return m.errorFmt != ""
}

func Test_FailNowWithPlainTestingT(t *testing.T) {
    mockT := &mockTestingT{}

    Panics(t, func() {
        FailNow(mockT, "failed")
    }, "should panic since mockT is missing FailNow()")
}

type mockFailNowTestingT struct {
}

func (m *mockFailNowTestingT) Errorf(format string, args ...interface{}) {}

func (m *mockFailNowTestingT) FailNow() {}

func Test_FailNowWithFullTestingT(t *testing.T) {
    mockT := &mockFailNowTestingT{}

    NotPanics(t, func() {
        FailNow(mockT, "failed")
    }, "should call mockT.FailNow() rather than panicking")
}

func Test_BytesEqual(t *testing.T) {
    var cases = []struct {
        a, b []byte
    }{
        {make([]byte, 2), make([]byte, 2)},
        {make([]byte, 2), make([]byte, 2, 3)},
        {nil, make([]byte, 0)},
    }

    for i, c := range cases {
        Equal(t, reflect.DeepEqual(c.a, c.b), ObjectsAreEqual(c.a, c.b), "case %d failed", i+1)
    }
}

func testAutogeneratedFunction() {
    defer func() {
        if err := recover(); err == nil {
            panic("did not panic")
        }
        CallerInfo()
    }()
    t := struct {
        io.Closer
    }{}
    c := t
    c.Close()
}

func Test_CallerInfoWithAutogeneratedFunctions(t *testing.T) {
    NotPanics(t, func() {
        testAutogeneratedFunction()
    })
}

func Test_Zero(t *testing.T) {
    mockT := new(testing.T)

    for _, test := range zeros {
        True(t, Zero(mockT, test, "%#v is not the %v zero value", test, reflect.TypeOf(test)))
    }

    for _, test := range nonZeros {
        False(t, Zero(mockT, test, "%#v is not the %v zero value", test, reflect.TypeOf(test)))
    }
}

func Test_NotZero(t *testing.T) {
    mockT := new(testing.T)

    for _, test := range zeros {
        False(t, NotZero(mockT, test, "%#v is not the %v zero value", test, reflect.TypeOf(test)))
    }

    for _, test := range nonZeros {
        True(t, NotZero(mockT, test, "%#v is not the %v zero value", test, reflect.TypeOf(test)))
    }
}

func Test_ContainsNotContains(t *testing.T) {

    type A struct {
        Name, Value string
    }
    list := []string{"Foo", "Bar"}

    complexList := []*A{
        {"b", "c"},
        {"d", "e"},
        {"g", "h"},
        {"j", "k"},
    }
    simpleMap := map[interface{}]interface{}{"Foo": "Bar"}
    var zeroMap map[interface{}]interface{}

    cases := []struct {
        expected interface{}
        actual   interface{}
        result   bool
    }{
        {"Hello World", "Hello", true},
        {"Hello World", "Salut", false},
        {list, "Bar", true},
        {list, "Salut", false},
        {complexList, &A{"g", "h"}, true},
        {complexList, &A{"g", "e"}, false},
        {simpleMap, "Foo", true},
        {simpleMap, "Bar", false},
        {zeroMap, "Bar", false},
    }

    for _, c := range cases {
        t.Run(fmt.Sprintf("Contains(%#v, %#v)", c.expected, c.actual), func(t *testing.T) {
            mockT := new(testing.T)
            res := Contains(mockT, c.expected, c.actual)

            if res != c.result {
                if res {
                    t.Errorf("Contains(%#v, %#v) should return true:\n\t%#v contains %#v", c.expected, c.actual, c.expected, c.actual)
                } else {
                    t.Errorf("Contains(%#v, %#v) should return false:\n\t%#v does not contain %#v", c.expected, c.actual, c.expected, c.actual)
                }
            }
        })
    }

    for _, c := range cases {
        t.Run(fmt.Sprintf("NotContains(%#v, %#v)", c.expected, c.actual), func(t *testing.T) {
            mockT := new(testing.T)
            res := NotContains(mockT, c.expected, c.actual)

            // NotContains should be inverse of Contains. If it's not, something is wrong
            if res == Contains(mockT, c.expected, c.actual) {
                if res {
                    t.Errorf("NotContains(%#v, %#v) should return true:\n\t%#v does not contains %#v", c.expected, c.actual, c.expected, c.actual)
                } else {
                    t.Errorf("NotContains(%#v, %#v) should return false:\n\t%#v contains %#v", c.expected, c.actual, c.expected, c.actual)
                }
            }
        })
    }
}

func Test_ContainsNotContainsFailMessage(t *testing.T) {
    mockT := new(mockTestingT)

    type nonContainer struct {
        Value string
    }

    cases := []struct {
        assertion func(t TestingT, s, contains interface{}, msgAndArgs ...interface{}) bool
        container interface{}
        instance  interface{}
        expected  string
    }{
        {
            assertion: Contains,
            container: "Hello World",
            instance:  errors.New("Hello"),
            expected:  "\"Hello World\" does not contain &errors.errorString{s:\"Hello\"}",
        },
        {
            assertion: Contains,
            container: map[string]int{"one": 1},
            instance:  "two",
            expected:  "map[string]int{\"one\":1} does not contain \"two\"\n",
        },
        {
            assertion: NotContains,
            container: map[string]int{"one": 1},
            instance:  "one",
            expected:  "map[string]int{\"one\":1} should not contain \"one\"",
        },
        {
            assertion: Contains,
            container: nonContainer{Value: "Hello"},
            instance:  "Hello",
            expected:  "test.nonContainer{Value:\"Hello\"} could not be applied builtin len()\n",
        },
        {
            assertion: NotContains,
            container: nonContainer{Value: "Hello"},
            instance:  "Hello",
            expected:  "test.nonContainer{Value:\"Hello\"} could not be applied builtin len()\n",
        },
    }

    for _, c := range cases {
        name := filepath.Base(runtime.FuncForPC(reflect.ValueOf(c.assertion).Pointer()).Name())
        t.Run(fmt.Sprintf("%v(%T, %T)", name, c.container, c.instance), func(t *testing.T) {
            c.assertion(mockT, c.container, c.instance)
            actualFail := mockT.errorString()
            if !strings.Contains(actualFail, c.expected) {
                t.Errorf("Contains failure should include %q but was %q", c.expected, actualFail)
            }
        })
    }
}

func Test_ContainsNotContainsOnNilValue(t *testing.T) {
    mockT := new(mockTestingT)

    Contains(mockT, nil, "key")
    expectedFail := "<nil> could not be applied builtin len()"
    actualFail := mockT.errorString()
    if !strings.Contains(actualFail, expectedFail) {
        t.Errorf("Contains failure should include %q but was %q", expectedFail, actualFail)
    }

    NotContains(mockT, nil, "key")
    if !strings.Contains(actualFail, expectedFail) {
        t.Errorf("Contains failure should include %q but was %q", expectedFail, actualFail)
    }
}

func Test_SubsetNotSubset(t *testing.T) {
    cases := []struct {
        list    interface{}
        subset  interface{}
        result  bool
        message string
    }{
        // cases that are expected to contain
        {[]int{1, 2, 3}, nil, true, `nil is the empty set which is a subset of every set`},
        {[]int{1, 2, 3}, []int{}, true, `[] is a subset of ['\x01' '\x02' '\x03']`},
        {[]int{1, 2, 3}, []int{1, 2}, true, `['\x01' '\x02'] is a subset of ['\x01' '\x02' '\x03']`},
        {[]int{1, 2, 3}, []int{1, 2, 3}, true, `['\x01' '\x02' '\x03'] is a subset of ['\x01' '\x02' '\x03']`},
        {[]string{"hello", "world"}, []string{"hello"}, true, `["hello"] is a subset of ["hello" "world"]`},
        {map[string]string{
            "a": "x",
            "c": "z",
            "b": "y",
        }, map[string]string{
            "a": "x",
            "b": "y",
        }, true, `map["a":"x" "b":"y"] is a subset of map["a":"x" "b":"y" "c":"z"]`},

        // cases that are expected not to contain
        {[]string{"hello", "world"}, []string{"hello", "testify"}, false, `[]string{"hello", "world"} does not contain "testify"`},
        {[]int{1, 2, 3}, []int{4, 5}, false, `[]int{1, 2, 3} does not contain 4`},
        {[]int{1, 2, 3}, []int{1, 5}, false, `[]int{1, 2, 3} does not contain 5`},
        {map[string]string{
            "a": "x",
            "c": "z",
            "b": "y",
        }, map[string]string{
            "a": "x",
            "b": "z",
        }, false, `map[string]string{"a":"x", "b":"y", "c":"z"} does not contain map[string]string{"a":"x", "b":"z"}`},
        {map[string]string{
            "a": "x",
            "b": "y",
        }, map[string]string{
            "a": "x",
            "b": "y",
            "c": "z",
        }, false, `map[string]string{"a":"x", "b":"y"} does not contain map[string]string{"a":"x", "b":"y", "c":"z"}`},
    }

    for _, c := range cases {
        t.Run("SubSet: "+c.message, func(t *testing.T) {

            mockT := new(mockTestingT)
            res := Subset(mockT, c.list, c.subset)

            if res != c.result {
                t.Errorf("Subset should return %t: %s", c.result, c.message)
            }
            if !c.result {
                expectedFail := c.message
                actualFail := mockT.errorString()
                if !strings.Contains(actualFail, expectedFail) {
                    t.Log(actualFail)
                    t.Errorf("Subset failure should contain %q but was %q", expectedFail, actualFail)
                }
            }
        })
    }
    for _, c := range cases {
        t.Run("NotSubSet: "+c.message, func(t *testing.T) {
            mockT := new(mockTestingT)
            res := NotSubset(mockT, c.list, c.subset)

            // NotSubset should match the inverse of Subset. If it doesn't, something is wrong
            if res == Subset(mockT, c.list, c.subset) {
                t.Errorf("NotSubset should return %t: %s", !c.result, c.message)
            }
            if c.result {
                expectedFail := c.message
                actualFail := mockT.errorString()
                if !strings.Contains(actualFail, expectedFail) {
                    t.Log(actualFail)
                    t.Errorf("NotSubset failure should contain %q but was %q", expectedFail, actualFail)
                }
            }
        })
    }
}

func Test_NotSubsetNil(t *testing.T) {
    mockT := new(testing.T)
    NotSubset(mockT, []string{"foo"}, nil)
    if !mockT.Failed() {
        t.Error("NotSubset on nil set should have failed the test")
    }
}

func Test_containsElement(t *testing.T) {

    list1 := []string{"Foo", "Bar"}
    list2 := []int{1, 2}
    simpleMap := map[interface{}]interface{}{"Foo": "Bar"}

    ok, found := containsElement("Hello World", "World")
    True(t, ok)
    True(t, found)

    ok, found = containsElement(list1, "Foo")
    True(t, ok)
    True(t, found)

    ok, found = containsElement(list1, "Bar")
    True(t, ok)
    True(t, found)

    ok, found = containsElement(list2, 1)
    True(t, ok)
    True(t, found)

    ok, found = containsElement(list2, 2)
    True(t, ok)
    True(t, found)

    ok, found = containsElement(list1, "Foo!")
    True(t, ok)
    False(t, found)

    ok, found = containsElement(list2, 3)
    True(t, ok)
    False(t, found)

    ok, found = containsElement(list2, "1")
    True(t, ok)
    False(t, found)

    ok, found = containsElement(simpleMap, "Foo")
    True(t, ok)
    True(t, found)

    ok, found = containsElement(simpleMap, "Bar")
    True(t, ok)
    False(t, found)

    ok, found = containsElement(1433, "1")
    False(t, ok)
    False(t, found)
}

// parseLabeledOutput does the inverse of labeledOutput - it takes a formatted
// output string and turns it back into a slice of labeledContent.
func parseLabeledOutput(output string) []labeledContent {
    labelPattern := regexp.MustCompile(`^\t([^\t]*): *\t(.*)$`)
    contentPattern := regexp.MustCompile(`^\t *\t(.*)$`)
    var contents []labeledContent
    lines := strings.Split(output, "\n")
    i := -1
    for _, line := range lines {
        if line == "" {
            // skip blank lines
            continue
        }
        matches := labelPattern.FindStringSubmatch(line)
        if len(matches) == 3 {
            // a label
            contents = append(contents, labeledContent{
                label:   matches[1],
                content: matches[2] + "\n",
            })
            i++
            continue
        }
        matches = contentPattern.FindStringSubmatch(line)
        if len(matches) == 2 {
            // just content
            if i >= 0 {
                contents[i].content += matches[1] + "\n"
                continue
            }
        }
        // Couldn't parse output
        return nil
    }
    return contents
}

type captureTestingT struct {
    msg string
}

func (ctt *captureTestingT) Errorf(format string, args ...interface{}) {
    ctt.msg = fmt.Sprintf(format, args...)
}

func (ctt *captureTestingT) checkResultAndErrMsg(t *testing.T, expectedRes, res bool, expectedErrMsg string) {
    t.Helper()
    if res != expectedRes {
        t.Errorf("Should return %t", expectedRes)
        return
    }
    contents := parseLabeledOutput(ctt.msg)
    if res == true {
        if contents != nil {
            t.Errorf("Should not log an error")
        }
        return
    }
    if contents == nil {
        t.Errorf("Should log an error. Log output: %v", ctt.msg)
        return
    }
    for _, content := range contents {
        if content.label == "Error" {
            if expectedErrMsg == content.content {
                return
            }
            t.Errorf("Logged Error: %v", content.content)
        }
    }
    t.Errorf("Should log Error: %v", expectedErrMsg)
}

func Test_ErrorIs(t *testing.T) {
    tests := []struct {
        err          error
        target       error
        result       bool
        resultErrMsg string
    }{
        {
            err:    io.EOF,
            target: io.EOF,
            result: true,
        },
        {
            err:    fmt.Errorf("wrap: %w", io.EOF),
            target: io.EOF,
            result: true,
        },
        {
            err:    io.EOF,
            target: io.ErrClosedPipe,
            result: false,
            resultErrMsg: "" +
                "Target error should be in err chain:\n" +
                "expected: \"io: read/write on closed pipe\"\n" +
                "in chain: \"EOF\"\n",
        },
        {
            err:    nil,
            target: io.EOF,
            result: false,
            resultErrMsg: "" +
                "Target error should be in err chain:\n" +
                "expected: \"EOF\"\n" +
                "in chain: \n",
        },
        {
            err:    io.EOF,
            target: nil,
            result: false,
            resultErrMsg: "" +
                "Target error should be in err chain:\n" +
                "expected: \"\"\n" +
                "in chain: \"EOF\"\n",
        },
        {
            err:    nil,
            target: nil,
            result: true,
        },
        {
            err:    fmt.Errorf("abc: %w", errors.New("def")),
            target: io.EOF,
            result: false,
            resultErrMsg: "" +
                "Target error should be in err chain:\n" +
                "expected: \"EOF\"\n" +
                "in chain: \"abc: def\"\n" +
                "\t\"def\"\n",
        },
    }
    for _, tt := range tests {
        tt := tt
        t.Run(fmt.Sprintf("ErrorIs(%#v,%#v)", tt.err, tt.target), func(t *testing.T) {
            mockT := new(captureTestingT)
            res := ErrorIs(mockT, tt.err, tt.target)
            mockT.checkResultAndErrMsg(t, tt.result, res, tt.resultErrMsg)
        })
    }
}

func Test_NotErrorIs(t *testing.T) {
    tests := []struct {
        err          error
        target       error
        result       bool
        resultErrMsg string
    }{
        {
            err:    io.EOF,
            target: io.EOF,
            result: false,
            resultErrMsg: "" +
                "Target error should not be in err chain:\n" +
                "found: \"EOF\"\n" +
                "in chain: \"EOF\"\n",
        },
        {
            err:    fmt.Errorf("wrap: %w", io.EOF),
            target: io.EOF,
            result: false,
            resultErrMsg: "" +
                "Target error should not be in err chain:\n" +
                "found: \"EOF\"\n" +
                "in chain: \"wrap: EOF\"\n" +
                "\t\"EOF\"\n",
        },
        {
            err:    io.EOF,
            target: io.ErrClosedPipe,
            result: true,
        },
        {
            err:    nil,
            target: io.EOF,
            result: true,
        },
        {
            err:    io.EOF,
            target: nil,
            result: true,
        },
        {
            err:    nil,
            target: nil,
            result: false,
            resultErrMsg: "" +
                "Target error should not be in err chain:\n" +
                "found: \"\"\n" +
                "in chain: \n",
        },
        {
            err:    fmt.Errorf("abc: %w", errors.New("def")),
            target: io.EOF,
            result: true,
        },
    }
    for _, tt := range tests {
        tt := tt
        t.Run(fmt.Sprintf("NotErrorIs(%#v,%#v)", tt.err, tt.target), func(t *testing.T) {
            mockT := new(captureTestingT)
            res := NotErrorIs(mockT, tt.err, tt.target)
            mockT.checkResultAndErrMsg(t, tt.result, res, tt.resultErrMsg)
        })
    }
}

func Test_ErrorAs(t *testing.T) {
    tests := []struct {
        err    error
        result bool
    }{
        {fmt.Errorf("wrap: %w", &customError{}), true},
        {io.EOF, false},
        {nil, false},
    }
    for _, tt := range tests {
        tt := tt
        var target *customError
        t.Run(fmt.Sprintf("ErrorAs(%#v,%#v)", tt.err, target), func(t *testing.T) {
            mockT := new(testing.T)
            res := ErrorAs(mockT, tt.err, &target)
            if res != tt.result {
                t.Errorf("ErrorAs(%#v,%#v) should return %t", tt.err, target, tt.result)
            }
            if res == mockT.Failed() {
                t.Errorf("The test result (%t) should be reflected in the testing.T type (%t)", res, !mockT.Failed())
            }
        })
    }
}

func Test_NotErrorAs(t *testing.T) {
    tests := []struct {
        err    error
        result bool
    }{
        {fmt.Errorf("wrap: %w", &customError{}), false},
        {io.EOF, true},
        {nil, true},
    }
    for _, tt := range tests {
        tt := tt
        var target *customError
        t.Run(fmt.Sprintf("NotErrorAs(%#v,%#v)", tt.err, target), func(t *testing.T) {
            mockT := new(testing.T)
            res := NotErrorAs(mockT, tt.err, &target)
            if res != tt.result {
                t.Errorf("NotErrorAs(%#v,%#v) should not return %t", tt.err, target, tt.result)
            }
            if res == mockT.Failed() {
                t.Errorf("The test result (%t) should be reflected in the testing.T type (%t)", res, !mockT.Failed())
            }
        })
    }
}

func Test_ComparisonAssertionFunc(t *testing.T) {
    type iface interface {
        Name() string
    }

    tests := []struct {
        name      string
        expect    interface{}
        got       interface{}
        assertion ComparisonAssertionFunc
    }{
        {"isType", (*testing.T)(nil), t, IsType},
        {"equal", t, t, Equal},
        {"equalValues", t, t, EqualValues},
        {"notEqualValues", t, nil, NotEqualValues},
        {"exactly", t, t, Exactly},
        {"notEqual", t, nil, NotEqual},
        {"notContains", []int{1, 2, 3}, 4, NotContains},
        {"subset", []int{1, 2, 3, 4}, []int{2, 3}, Subset},
        {"notSubset", []int{1, 2, 3, 4}, []int{0, 3}, NotSubset},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            tt.assertion(t, tt.expect, tt.got)
        })
    }
}

func Test_ValueAssertionFunc(t *testing.T) {
    tests := []struct {
        name      string
        value     interface{}
        assertion ValueAssertionFunc
    }{
        {"notNil", true, NotNil},
        {"nil", nil, Nil},
        {"empty", []int{}, Empty},
        {"notEmpty", []int{1}, NotEmpty},
        {"zero", false, Zero},
        {"notZero", 42, NotZero},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            tt.assertion(t, tt.value)
        })
    }
}

func Test_BoolAssertionFunc(t *testing.T) {
    tests := []struct {
        name      string
        value     bool
        assertion BoolAssertionFunc
    }{
        {"true", true, True},
        {"false", false, False},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            tt.assertion(t, tt.value)
        })
    }
}

func Test_WithinDuration(t *testing.T) {

    mockT := new(testing.T)
    a := time.Now()
    b := a.Add(10 * time.Second)

    True(t, WithinDuration(mockT, a, b, 10*time.Second), "A 10s difference is within a 10s time difference")
    True(t, WithinDuration(mockT, b, a, 10*time.Second), "A 10s difference is within a 10s time difference")

    False(t, WithinDuration(mockT, a, b, 9*time.Second), "A 10s difference is not within a 9s time difference")
    False(t, WithinDuration(mockT, b, a, 9*time.Second), "A 10s difference is not within a 9s time difference")

    False(t, WithinDuration(mockT, a, b, -9*time.Second), "A 10s difference is not within a 9s time difference")
    False(t, WithinDuration(mockT, b, a, -9*time.Second), "A 10s difference is not within a 9s time difference")

    False(t, WithinDuration(mockT, a, b, -11*time.Second), "A 10s difference is not within a 9s time difference")
    False(t, WithinDuration(mockT, b, a, -11*time.Second), "A 10s difference is not within a 9s time difference")
}

func Test_WithinRange(t *testing.T) {

    mockT := new(testing.T)
    n := time.Now()
    s := n.Add(-time.Second)
    e := n.Add(time.Second)

    True(t, WithinRange(mockT, n, n, n), "Exact same actual, start, and end values return true")

    True(t, WithinRange(mockT, n, s, e), "Time in range is within the time range")
    True(t, WithinRange(mockT, s, s, e), "The start time is within the time range")
    True(t, WithinRange(mockT, e, s, e), "The end time is within the time range")

    False(t, WithinRange(mockT, s.Add(-time.Nanosecond), s, e, "Just before the start time is not within the time range"))
    False(t, WithinRange(mockT, e.Add(time.Nanosecond), s, e, "Just after the end time is not within the time range"))

    False(t, WithinRange(mockT, n, e, s, "Just after the end time is not within the time range"))
}
