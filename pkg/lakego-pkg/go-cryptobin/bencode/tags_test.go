package bencode

import (
    "testing"
    "reflect"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_getTag(t *testing.T) {
    eq := cryptobin_test.AssertEqualT(t)

    type S struct {
        A string `bencode:"a,omitempty"`
        B string `bencode:"b,ignore_unmarshal_type_error"`
        E string `bencode:"-"`
        F string `bencode:"go-cryptobin,ddd" color:"blue,red" lang`
    }

    s := S{}
    st := reflect.TypeOf(s)

    newData1 := getTag(st.Field(0).Tag)
    eq(newData1.Ignore(), false, "Test_getTag-newData1-Ignore")
    eq(newData1.Key(), "a", "Test_getTag-newData1-Key")
    eq(newData1.OmitEmpty(), true, "Test_getTag-newData1-OmitEmpty")

    newData2 := getTag(st.Field(1).Tag)
    eq(newData2.Ignore(), false, "Test_getTag-newData2-Ignore")
    eq(newData2.Key(), "b", "Test_getTag-newData2-Key")
    eq(newData2.IgnoreUnmarshalTypeError(), true, "Test_getTag-newData2-IgnoreUnmarshalTypeError")

    newData3 := getTag(st.Field(2).Tag)
    eq(newData3.Ignore(), true, "Test_getTag-newData3-Ignore")

    newData31 := getTag(st.Field(3).Tag)
    eq(newData31.HasOpt("ddd"), true, "Test_getTag-newData31-HasOpt")
}
