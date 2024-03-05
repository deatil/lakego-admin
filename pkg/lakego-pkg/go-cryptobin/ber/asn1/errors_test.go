package asn1

import (
    "reflect"
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_UnsupportedTypeError(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    mte := &UnsupportedTypeError{
        Type: reflect.TypeOf("test"),
    }

    check := "asn1: unsupported type: string"
    assertEqual(mte.Error(), check, "Test_UnsupportedTypeError")
}

func Test_SyntaxError(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    mte := &SyntaxError{
        Msg: "test msg",
    }

    check := "asn1: syntax error: test msg"
    assertEqual(mte.Error(), check, "Test_SyntaxError")
}

func Test_StructuralError(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    mte := &StructuralError{
        Msg: "test msg",
    }

    check := "asn1: structure error: test msg"
    assertEqual(mte.Error(), check, "Test_StructuralError")
}
