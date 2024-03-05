package bencode

import (
    "reflect"
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_IsEmptyValue(t *testing.T) {
    eq := cryptobin_test.AssertEqualT(t)

    type S struct {
        F string `bencode:"go-cryptobin,ddd" color:"blue,red" lang`
    }

    var tmap map[string]string
    var tslice []string
    var tarray []byte
    var tStruct S
    var tfunc = func(){}

    tfunc = nil

    eq(IsEmptyValue(reflect.ValueOf(tmap)), true, "Test_IsEmptyValue-1")
    eq(IsEmptyValue(reflect.ValueOf(tslice)), true, "Test_IsEmptyValue-2")
    eq(IsEmptyValue(reflect.ValueOf(tarray)), true, "Test_IsEmptyValue-3")
    eq(IsEmptyValue(reflect.ValueOf(tStruct)), true, "Test_IsEmptyValue-31")
    eq(IsEmptyValue(reflect.ValueOf(tfunc)), true, "Test_IsEmptyValue-5")
    eq(IsEmptyValue(reflect.ValueOf(0)), true, "Test_IsEmptyValue-6")
}
