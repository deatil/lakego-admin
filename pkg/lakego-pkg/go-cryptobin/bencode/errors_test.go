package bencode

import (
    "errors"
    "reflect"
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_MarshalTypeError(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    mte := &MarshalTypeError{
        Type: reflect.TypeOf("name"),
    }

    check := "bencode: unsupported type: string"
    assertEqual(mte.Error(), check, "Test_MarshalTypeError")
}

type testPtr struct{}

func Test_UnmarshalInvalidArgError(t *testing.T) {
    eq := cryptobin_test.AssertEqualT(t)

    tests := []struct {
        index string
        typ   reflect.Type
        check string
    }{
        {
            index: "index-1",
            typ: reflect.TypeOf(nil),
            check: "bencode: Unmarshal(nil)",
        },
        {
            index: "index-1",
            typ: reflect.TypeOf("name"),
            check: "bencode: Unmarshal(non-pointer string)",
        },
        {
            index: "index-1",
            typ: reflect.TypeOf(&testPtr{}),
            check: "bencode: Unmarshal(nil *bencode.testPtr)",
        },
    }

    for _, td := range tests {
        mte := &UnmarshalInvalidArgError{
            Type: td.typ,
        }

        check := mte.Error()

        eq(check, td.check, "UnmarshalInvalidArgError Eq, index "+td.index)
    }
}

func Test_UnmarshalTypeError(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    te := &UnmarshalTypeError{
        BencodeTypeName: "test name",
        UnmarshalTargetType: reflect.TypeOf(11),
    }

    check := "can't unmarshal a bencode test name into a int"
    assertEqual(te.Error(), check, "Test_UnmarshalTypeError")
}

func Test_UnmarshalFieldError(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    te := &UnmarshalFieldError{
        Key: "test",
        Type: reflect.TypeOf(11),
        Field: reflect.StructField{Name: "12", Type: reflect.TypeOf(0)},
    }

    check := `bencode: key "test" led to an unexported field "12" in type: int`
    assertEqual(te.Error(), check, "Test_UnmarshalFieldError")
}

func Test_SyntaxError(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    te := &SyntaxError{
        Offset: 11,
        What: errors.New("test"),
    }

    check := "bencode: syntax error (offset: 11): test"
    assertEqual(te.Error(), check, "Test_SyntaxError")
}

func Test_MarshalerError(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    me := &MarshalerError{
        Type: reflect.TypeOf("name"),
        Err: errors.New("test"),
    }

    check := "bencode: error calling MarshalBencode for type string: test"
    assertEqual(me.Error(), check, "Test_MarshalerError")
}

func Test_UnmarshalerError(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    me := &UnmarshalerError{
        Type: reflect.TypeOf("name"),
        Err: errors.New("test"),
    }

    check := "bencode: error calling UnmarshalBencode for type string: test"
    assertEqual(me.Error(), check, "Test_UnmarshalerError")
}

func Test_UnusedTrailingBytesError(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    me := &UnusedTrailingBytesError{
        NumUnusedBytes: 22,
    }

    check := "22 unused trailing bytes"
    assertEqual(me.Error(), check, "Test_UnusedTrailingBytesError")
}
