package array

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

var (
	arrData = map[string]any{
		"a": 123,
		"b": map[string]any{
			"c": "ccc",
			"d": map[string]any{
				"e": "eee",
				"f": map[string]any{
					"g": "ggg",
				},
			},
			"dd": []any{
				"ccccc",
				"ddddd",
				"fffff",
			},
			"ddd": []int64{
				22,
				333,
				555,
			},
			"ff": map[any]any{
				111: "fccccc",
				222: "fddddd",
				333: "dfffff",
			},
			"hhTy3": &map[int]any{
				111: "hccccc",
				222: "hddddd",
				333: map[any]string{
					"qq1": "qq1ccccc",
					"qq2": "qq2ddddd",
					"qq3": "qq3fffff",
				},
				666: []float64{
					12.3,
					32.5,
					22.56,
					789.156,
				},
			},
			"hhTy66": &map[int]any{
				777: &[]float64{
					12.3,
					32.5,
					22.56,
					789.156,
				},
			},
			"kJh21ay": map[string]any{
				"Hjk2": "fccDcc",
				"23rt": "^hgcF5c",
				"23rt5": []any{
					"adfa",
					1231,
				},
			},
			"kJh21ay22": map[int64]any{
				33: []any{
					"adfa",
					1231,
				},
			},
		},
	}
)

func assertT(t *testing.T) func(any, string, string) {
	return func(actual any, expected string, msg string) {
		actualStr := toString(actual)
		if actualStr != expected {
			t.Errorf("Failed %s: actual: %v, expected: %v", msg, actualStr, expected)
		}
	}
}

func assertDeepEqualT(t *testing.T) func(any, any, string) {
	return func(actual any, expected any, msg string) {
		if !reflect.DeepEqual(actual, expected) {
			t.Errorf("Failed %s: actual: %v, expected: %v", msg, actual, expected)
		}
	}
}

func Test_WithKeyDelim(t *testing.T) {
	assert := assertT(t)

	testData := []struct {
		index    string
		keyDelim string
		check    string
	}{
		{
			"index-1",
			"a",
			"a",
		},
		{
			"index-2",
			"-",
			"-",
		},
	}

	for _, v := range testData {
		arr := New("").WithKeyDelim(v.keyDelim)

		assert(arr.keyDelim, v.check, "WithKeyDelim fail, index "+v.index)
	}

}

func Test_Exists(t *testing.T) {
	testData := []struct {
		index string
		key   string
		check bool
	}{
		{
			"index-1",
			"a",
			true,
		},
		{
			"index-2",
			"b.dd.1",
			true,
		},
		{
			"index-3",
			"b.ff.222333",
			false,
		},
		{
			"index-4",
			"b.hhTy3.222.yu",
			false,
		},
		{
			"index-5",
			"b.hhTy3.333.qq2",
			true,
		},
	}

	for _, v := range testData {
		check := New(arrData).Exists(v.key)
		if check != v.check {
			t.Error("Exists fail, index " + v.index)
		}
	}

}

func Test_Exists_func(t *testing.T) {
	testData := []struct {
		index string
		key   string
		check bool
	}{
		{
			"index-1",
			"a",
			true,
		},
		{
			"index-2",
			"b.dd.1",
			true,
		},
		{
			"index-3",
			"b.ff.222333",
			false,
		},
		{
			"index-4",
			"b.hhTy3.222.yu",
			false,
		},
		{
			"index-5",
			"b.hhTy3.333.qq2",
			true,
		},
	}

	for _, v := range testData {
		check := Exists(arrData, v.key)
		if check != v.check {
			t.Error("Exists func fail, index " + v.index)
		}
	}

}

func Test_Get(t *testing.T) {
	assert := assertT(t)

	testData := []struct {
		key      string
		expected string
		def      string
		msg      string
	}{
		{
			"a",
			"123",
			"",
			"map[string]any",
		},
		{
			"b.dd.1",
			"ddddd",
			"",
			"[]any",
		},
		{
			"b.ff.222",
			"fddddd",
			"",
			"map[any]any",
		},
		{
			"b.hhTy3.222",
			"hddddd",
			"",
			"&map[int]any",
		},
		{
			"b.hhTy3.333.qq2",
			"qq2ddddd",
			"",
			"map[any]string",
		},
		{
			"b.hhTy3.666.3",
			"789.156",
			"",
			"Slice",
		},
		{
			"b.hhTy3.666.9999999",
			"222555",
			"222555",
			"default",
		},
	}

	for _, v := range testData {
		check := New(arrData).Get(v.key, v.def)

		assert(check, v.expected, v.msg)
	}

	check2 := New(arrData).Get("b.hhTy3.666.65555")
	assert(check2, "", "nil")
}

func Test_Get_func(t *testing.T) {
	assert := assertT(t)

	testData := []struct {
		key      string
		expected string
		def      string
		msg      string
	}{
		{
			"a",
			"123",
			"",
			"map[string]any",
		},
		{
			"b.dd.1",
			"ddddd",
			"",
			"[]any",
		},
		{
			"b.ff.222",
			"fddddd",
			"",
			"map[any]any",
		},
		{
			"b.hhTy3.222",
			"hddddd",
			"",
			"&map[int]any",
		},
		{
			"b.hhTy3.333.qq2",
			"qq2ddddd",
			"",
			"map[any]string",
		},
		{
			"b.hhTy3.666.3",
			"789.156",
			"",
			"Slice",
		},
		{
			"b.hhTy3.666.9999999",
			"222555",
			"222555",
			"default",
		},
	}

	for _, v := range testData {
		check := Get(arrData, v.key, v.def)

		assert(check, v.expected, v.msg)
	}

}

func Test_Find(t *testing.T) {
	assert := assertT(t)

	testData := []struct {
		key      string
		expected string
		msg      string
	}{
		{
			"a",
			"123",
			"map[string]any",
		},
		{
			"b.dd.1",
			"ddddd",
			"[]any",
		},
		{
			"b.ff.222",
			"fddddd",
			"map[any]any",
		},
		{
			"b.hhTy3.222",
			"hddddd",
			"&map[int]any",
		},
		{
			"b.hhTy3.333.qq2",
			"qq2ddddd",
			"map[any]string",
		},
		{
			"b.hhTy3.666.3",
			"789.156",
			"Slice",
		},
	}

	for _, v := range testData {
		check := New(arrData).Find(v.key)

		assert(check, v.expected, v.msg)
	}

}

func Test_Find_func(t *testing.T) {
	assert := assertT(t)

	testData := []struct {
		key      string
		expected string
		msg      string
	}{
		{
			"a",
			"123",
			"map[string]any",
		},
		{
			"b.dd.1",
			"ddddd",
			"[]any",
		},
		{
			"b.ff.222",
			"fddddd",
			"map[any]any",
		},
		{
			"b.hhTy3.222",
			"hddddd",
			"&map[int]any",
		},
		{
			"b.hhTy3.333.qq2",
			"qq2ddddd",
			"map[any]string",
		},
		{
			"b.hhTy3.666.3",
			"789.156",
			"Slice",
		},
	}

	for _, v := range testData {
		check := Find(arrData, v.key)

		assert(check, v.expected, v.msg)
	}

}

func Test_Search(t *testing.T) {
	assert := assertT(t)

	testData := []struct {
		key      string
		expected string
		msg      string
	}{
		{
			"a",
			"123",
			"map[string]any",
		},
		{
			"b.dd.1",
			"ddddd",
			"[]any",
		},
		{
			"b.ff.222",
			"fddddd",
			"map[any]any",
		},
		{
			"b.hhTy3.222",
			"hddddd",
			"&map[int]any",
		},
		{
			"b.hhTy3.333.qq2",
			"qq2ddddd",
			"map[any]string",
		},
		{
			"b.hhTy3.666.3",
			"789.156",
			"Slice",
		},
	}

	for _, v := range testData {
		check := New(arrData).Search(strings.Split(v.key, ".")...).Value()

		assert(check, v.expected, v.msg)
	}

}

func Test_Search_func(t *testing.T) {
	assert := assertT(t)

	testData := []struct {
		key      string
		expected string
		msg      string
	}{
		{
			"a",
			"123",
			"map[string]any",
		},
		{
			"b.dd.1",
			"ddddd",
			"[]any",
		},
		{
			"b.ff.222",
			"fddddd",
			"map[any]any",
		},
		{
			"b.hhTy3.222",
			"hddddd",
			"&map[int]any",
		},
		{
			"b.hhTy3.333.qq2",
			"qq2ddddd",
			"map[any]string",
		},
		{
			"b.hhTy3.666.3",
			"789.156",
			"Slice",
		},
	}

	for _, v := range testData {
		check := Search(arrData, strings.Split(v.key, ".")...).Value()

		assert(check, v.expected, v.msg)
	}

}

func Test_ParseJSON(t *testing.T) {
	assert := assertT(t)

	jsonParsed, err := ParseJSON([]byte(`{
		"outer":{
			"inner":{
				"value1":21,
				"value2":35
			},
			"alsoInner":{
				"value1":99,
				"array1":[
					11, 23
				]
			}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}

	value := jsonParsed.Find("outer.inner.value1")
	expected := "21"

	assert(value, expected, "ParseJSON fail")

	value2 := jsonParsed.Find("outer.alsoInner.array1.1")
	expected2 := "23"

	assert(value2, expected2, "ParseJSON 2 fail")
}

func Test_Sub_And_Value(t *testing.T) {
	assert := assertT(t)

	testData := []struct {
		key      string
		expected string
		msg      string
	}{
		{
			"a",
			"123",
			"map[string]any",
		},
		{
			"b.dd.1",
			"ddddd",
			"[]any",
		},
		{
			"b.ff.222",
			"fddddd",
			"map[any]any",
		},
		{
			"b.hhTy3.222",
			"hddddd",
			"&map[int]any",
		},
		{
			"b.hhTy3.333.qq2",
			"qq2ddddd",
			"map[any]string",
		},
		{
			"b.hhTy3.666.3",
			"789.156",
			"Slice",
		},
	}

	for _, v := range testData {
		check := New(arrData).Sub(v.key).Value()

		assert(check, v.expected, v.msg)
	}

}

func Test_Sub_And_Value_func(t *testing.T) {
	assert := assertT(t)

	testData := []struct {
		key      string
		expected string
		msg      string
	}{
		{
			"a",
			"123",
			"map[string]any",
		},
		{
			"b.dd.1",
			"ddddd",
			"[]any",
		},
		{
			"b.ff.222",
			"fddddd",
			"map[any]any",
		},
		{
			"b.hhTy3.222",
			"hddddd",
			"&map[int]any",
		},
		{
			"b.hhTy3.333.qq2",
			"qq2ddddd",
			"map[any]string",
		},
		{
			"b.hhTy3.666.3",
			"789.156",
			"Slice",
		},
	}

	for _, v := range testData {
		check := Sub(arrData, v.key).Value()

		assert(check, v.expected, v.msg)
	}

}

func Test_Sub_And_ToJSON(t *testing.T) {
	assert := assertT(t)

	testData := []struct {
		key      string
		expected string
		msg      string
	}{
		{
			"b.dd",
			`["ccccc","ddddd","fffff"]`,
			"[]any",
		},
		{
			"b.d",
			`{"e":"eee","f":{"g":"ggg"}}`,
			"map[any]any",
		},
		{
			"b.hhTy3.333",
			`{"qq1":"qq1ccccc","qq2":"qq2ddddd","qq3":"qq3fffff"}`,
			"&map[int]any",
		},
		{
			"b.hhTy3",
			`null`,
			"null",
		},
	}

	for _, v := range testData {
		check := New(arrData).Sub(v.key).ToJSON()

		assert(check, v.expected, v.msg)
	}

}

func Test_Sub_And_ToJSONIndent(t *testing.T) {
	assert := assertT(t)

	testData := []struct {
		key      string
		expected string
		msg      string
	}{
		{
			"b.dd",
			`[
  "ccccc",
  "ddddd",
  "fffff"
]`,
			"[]any",
		},
		{
			"b.d",
			`{
  "e": "eee",
  "f": {
    "g": "ggg"
  }
}`,
			"map[any]any",
		},
		{
			"b.hhTy3.333",
			`{
  "qq1": "qq1ccccc",
  "qq2": "qq2ddddd",
  "qq3": "qq3fffff"
}`,
			"&map[int]any",
		},
		{
			"b.d222",
			`null`,
			"null",
		},
	}

	for _, v := range testData {
		check := New(arrData).Sub(v.key).ToJSONIndent("", "  ")

		assert(check, v.expected, v.msg)
	}

}

func Test_Sub_And_MarshalJSON(t *testing.T) {
	assert := assertT(t)

	testData := []struct {
		key      string
		expected string
		msg      string
	}{
		{
			"b.dd",
			`["ccccc","ddddd","fffff"]`,
			"[]any",
		},
		{
			"b.d",
			`{"e":"eee","f":{"g":"ggg"}}`,
			"map[any]any",
		},
		{
			"b.hhTy3.333",
			`{"qq1":"qq1ccccc","qq2":"qq2ddddd","qq3":"qq3fffff"}`,
			"&map[int]any",
		},
		{
			"b.hhTy3",
			``,
			"null",
		},
	}

	for _, v := range testData {
		check, _ := New(arrData).Sub(v.key).MarshalJSON()

		assert(check, v.expected, v.msg)
	}

}

func Test_Children(t *testing.T) {
	jsonParsed, _ := ParseJSON([]byte(`{"map":{"objectOne":{"num":1}}, "array":[ "first", "second", "third" ]}`))

	expected := []string{"first", "second", "third"}

	childrenNil := jsonParsed.Sub("array123132").Children()
	if childrenNil != nil {
		t.Error("Child need return nil")
	}

	children := jsonParsed.Sub("array").Children()
	for i, child := range children {
		if expected[i] != child.Value().(string) {
			t.Errorf("Child unexpected: %v != %v", expected[i], child.Value().(string))
		}
	}

	mapChildren := jsonParsed.Sub("map").Children()
	for key, val := range mapChildren {
		switch key {
		case 0:
			if val := val.Sub("num").Value().(float64); val != 1 {
				t.Errorf("%v != %v", val, 1)
			}
		default:
			t.Errorf("Unexpected key: %v", key)
		}
	}
}

func Test_ChildrenMap(t *testing.T) {
	json1, _ := ParseJSON([]byte(`{
		"objectOne":{"num":1},
		"objectTwo":{"num":2},
		"objectThree":{"num":3}
	}`))

	objectMap := json1.ChildrenMap()
	if len(objectMap) != 3 {
		t.Errorf("Wrong num of elements in objectMap: %v != %v", len(objectMap), 3)
		return
	}

	ChildrenMapNil := json1.Sub("array123132").ChildrenMap()
	if len(ChildrenMapNil) != 0 {
		t.Error("Child need return map[string]*Array{}")
	}

	for key, val := range objectMap {
		switch key {
		case "objectOne":
			if val := val.Sub("num").Value().(float64); val != 1 {
				t.Errorf("%v != %v", val, 1)
			}
		case "objectTwo":
			if val := val.Sub("num").Value().(float64); val != 2 {
				t.Errorf("%v != %v", val, 2)
			}
		case "objectThree":
			if val := val.Sub("num").Value().(float64); val != 3 {
				t.Errorf("%v != %v", val, 3)
			}
		default:
			t.Errorf("Unexpected key: %v", key)
		}
	}
}

func Test_Flatten(t *testing.T) {
	assert := assertDeepEqualT(t)

	json1, _ := ParseJSON([]byte(`{"foo":[{"bar":"1"},{"bar":"2"}]}`))

	flattenData, err := json1.Flatten()
	if err != nil {
		t.Fatal(err)
	}

	check := map[string]any{
		"foo.0.bar": "1",
		"foo.1.bar": "2",
	}

	assert(flattenData, check, "Flatten fail")

	// =====

	flattenData2, err := json1.Sub("foo").Flatten()
	if err != nil {
		t.Fatal(err)
	}

	check2 := map[string]any{
		"0.bar": "1",
		"1.bar": "2",
	}

	assert(flattenData2, check2, "Flatten 2 fail")
}

func Test_FlattenIncludeEmpty(t *testing.T) {
	assert := assertDeepEqualT(t)

	json1, _ := ParseJSON([]byte(`{"foo":[{"bar":"1"},{"bar":"2"},{"bar222":{}}]}`))

	flattenData, err := json1.FlattenIncludeEmpty()
	if err != nil {
		t.Fatal(err)
	}

	check := map[string]any{
		"foo.0.bar":    "1",
		"foo.1.bar":    "2",
		"foo.2.bar222": struct{}{},
	}

	assert(flattenData, check, "FlattenIncludeEmpty fail")
}

func Test_JSONPointer(t *testing.T) {
	assert := assertT(t)

	data := []byte(`{"foo":[{"bar":"1"},{"bar":"2"}]}`)

	json1, _ := ParseJSON(data)

	testData := []struct {
		key      string
		expected string
		msg      string
	}{
		{
			"/foo/0",
			`{"bar":"1"}`,
			"map[string]any",
		},
		{
			"/foo",
			`[{"bar":"1"},{"bar":"2"}]`,
			"[]any",
		},
		{
			"/foo/1",
			`{"bar":"2"}`,
			"map[string]any",
		},
		{
			"/foo/5",
			`null`,
			"not find",
		},
		{
			"/",
			`null`,
			"null",
		},
	}

	for _, v := range testData {
		check, err := json1.JSONPointer(v.key)
		if err != nil {
			t.Fatal(err)
		}

		assert(check.String(), v.expected, v.msg)
	}

	var dst any
	json.Unmarshal(data, &dst)

	for _, v := range testData {
		check, err := JSONPointer(dst, v.key)
		if err != nil {
			t.Fatal(err)
		}

		assert(check.String(), v.expected, v.msg)
	}

	_, err := json1.JSONPointer("foo/1")
	if err == nil {
		t.Error("value should not have been found in foo")
	}
}

func Test_Set(t *testing.T) {
	gObj := New(nil)

	if _, err := gObj.Set([]interface{}{}, "foo"); err != nil {
		t.Fatal(err)
	}
	if _, err := gObj.Set(1, "foo", "-"); err != nil {
		t.Fatal(err)
	}
	if _, err := gObj.Set([]interface{}{}, "foo", "-", "baz"); err != nil {
		t.Fatal(err)
	}
	if _, err := gObj.Set(2, "foo", "1", "baz", "-"); err != nil {
		t.Fatal(err)
	}
	if _, err := gObj.Set(3, "foo", "1", "baz", "-"); err != nil {
		t.Fatal(err)
	}
	if _, err := gObj.Set(5, "foo", "-"); err != nil {
		t.Fatal(err)
	}

	exp := `{"foo":[1,{"baz":[2,3]},5]}`
	if act := gObj.String(); act != exp {
		t.Errorf("Unexpected value: %v != %v", act, exp)
	}

	// ========

	arrData2 := map[string]any{
		"a": 123,
		"b": map[string]any{
			"c": "ccc",
			"d": map[string]any{
				"e": "eee",
				"f": map[string]any{
					"g": "ggg",
				},
			},
			"dd": []any{
				"ccccc",
				"ddddd",
				"fffff",
			},
			"ddd": []int64{
				22,
				333,
				555,
			},
			"ff": map[any]any{
				111: "fccccc",
				222: "fddddd",
				333: "dfffff",
			},
			"hhTy3": &map[int]any{
				111: "hccccc",
				222: "hddddd",
				333: map[any]string{
					"qq1": "qq1ccccc",
					"qq2": "qq2ddddd",
					"qq3": "qq3fffff",
				},
				666: []float64{
					12.3,
					32.5,
					22.56,
					789.156,
				},
			},
			"kJh21ay": map[string]any{
				"Hjk2": "fccDcc",
				"23rt": "^hgcF5c",
				"23rt5": []any{
					"adfa",
					1231,
				},
			},
		},
	}

	gObj2 := New(arrData2)
	if _, err := gObj2.Set(5, "b", "ff", 555); err != nil {
		t.Fatal(err)
	}
	if _, err := gObj2.Set("qqqqqqqqw", "b", "dd", "-"); err != nil {
		t.Fatal(err)
	}
	if _, err := gObj2.Set(float64(222.9999), "b", "hhTy3", int(666), 2); err != nil {
		t.Fatal(err)
	}

	exp2 := `{"111":"fccccc","222":"fddddd","333":"dfffff","555":5}`
	if act := gObj2.Sub("b.ff").String(); act != exp2 {
		t.Errorf("Unexpected value: %v != %v", act, exp2)
	}
	exp3 := `["ccccc","ddddd","fffff","qqqqqqqqw"]`
	if act := gObj2.Sub("b.dd").String(); act != exp3 {
		t.Errorf("Unexpected value: %v != %v", act, exp3)
	}
	exp5 := `[12.3,32.5,222.9999,789.156]`
	if act := gObj2.Sub("b.hhTy3.666").String(); act != exp5 {
		t.Errorf("Unexpected value: %v != %v", act, exp5)
	}

}

func Test_SetMap(t *testing.T) {
	obj := New(arrData)
	_, err := obj.Set("yyyyyyyyy", "b", "ff", "555")
	if err != nil {
		t.Fatal(err)
	}

	res := obj.Sub("b.ff").String()

	check := `{"111":"fccccc","222":"fddddd","333":"dfffff","555":"yyyyyyyyy"}`
	if res != check {
		t.Errorf("SetMap fail. got %v, want %v", res, check)
	}

	// =======

	obj1 := New(arrData)
	_, err = obj1.Set("yyyyyyyyy")
	if err != nil {
		t.Fatal(err)
	}

	res1 := fmt.Sprintf("%v", obj1.Value())

	check1 := `yyyyyyyyy`
	if res1 != check1 {
		t.Errorf("SetMap 1 fail. got %v, want %v", res1, check1)
	}

	// =======

	obj2 := New(arrData)
	_, err = obj2.Set(133.122333, "b", "hhTy3", 666)
	if err != nil {
		t.Fatal(err)
	}

	_, err = obj2.Set(133.122333, "b", "kJh21ay22", "ftd")
	if err == nil {
		t.Error("Set should error")
	}

	res2 := fmt.Sprintf("%v", obj2.Sub("b.hhTy3").Value())

	check2 := `&map[111:hccccc 222:hddddd 333:map[qq1:qq1ccccc qq2:qq2ddddd qq3:qq3fffff] 666:133.122333]`
	if res2 != check2 {
		t.Errorf("SetMap 2 fail. got %v, want %v", res2, check2)
	}
}

func Test_SetKey(t *testing.T) {
	obj := New(arrData)
	_, err := obj.SetKey("yyyyyyyyy", "b.ff.555")
	if err != nil {
		t.Fatal(err)
	}

	res := obj.Sub("b.ff").String()

	check := `{"111":"fccccc","222":"fddddd","333":"dfffff","555":"yyyyyyyyy"}`
	if res != check {
		t.Errorf("SetKey fail. got %v, want %v", res, check)
	}
}

func Test_ArraysTwo(t *testing.T) {
	json1 := New(nil)

	test1, err := json1.ArrayOfSize(4, "test1")
	if err != nil {
		t.Error(err)
	}

	if _, err = test1.ArrayOfSizeIndex(2, 0); err != nil {
		t.Error(err)
	}
	if _, err = test1.ArrayOfSizeIndex(2, 1); err != nil {
		t.Error(err)
	}
	if _, err = test1.ArrayOfSizeIndex(2, 2); err != nil {
		t.Error(err)
	}
	if _, err = test1.ArrayOfSizeIndex(2, 3); err != nil {
		t.Error(err)
	}

	if _, err = test1.ArrayOfSizeIndex(2, 4); err != ErrOutOfBounds {
		t.Errorf("Index should have been out of bounds")
	}

	if _, err = json1.Sub("test1").Index(0).SetIndex(10, 0); err != nil {
		t.Error(err)
	}
	if _, err = json1.Sub("test1").Index(0).SetIndex(11, 1); err != nil {
		t.Error(err)
	}

	if _, err = json1.Sub("test1").Index(1).SetIndex(12, 0); err != nil {
		t.Error(err)
	}
	if _, err = json1.Sub("test1").Index(1).SetIndex(13, 1); err != nil {
		t.Error(err)
	}

	if _, err = json1.Sub("test1").Index(2).SetIndex(14, 0); err != nil {
		t.Error(err)
	}
	if _, err = json1.Sub("test1").Index(2).SetIndex(15, 1); err != nil {
		t.Error(err)
	}

	if _, err = json1.Sub("test1").Index(3).SetIndex(16, 0); err != nil {
		t.Error(err)
	}
	if _, err = json1.Sub("test1").Index(3).SetIndex(17, 1); err != nil {
		t.Error(err)
	}

	if val := json1.Sub("test1").Index(0).Index(0).Value().(int); val != 10 {
		t.Errorf("create array: %v != %v", val, 10)
	}
	if val := json1.Sub("test1").Index(0).Index(1).Value().(int); val != 11 {
		t.Errorf("create array: %v != %v", val, 11)
	}

	if val := json1.Sub("test1").Index(1).Index(0).Value().(int); val != 12 {
		t.Errorf("create array: %v != %v", val, 12)
	}
	if val := json1.Sub("test1").Index(1).Index(1).Value().(int); val != 13 {
		t.Errorf("create array: %v != %v", val, 13)
	}

	if val := json1.Sub("test1").Index(2).Index(0).Value().(int); val != 14 {
		t.Errorf("create array: %v != %v", val, 14)
	}
	if val := json1.Sub("test1").Index(2).Index(1).Value().(int); val != 15 {
		t.Errorf("create array: %v != %v", val, 15)
	}

	if val := json1.Sub("test1").Index(3).Index(0).Value().(int); val != 16 {
		t.Errorf("create array: %v != %v", val, 16)
	}
	if val := json1.Sub("test1").Index(3).Index(1).Value().(int); val != 17 {
		t.Errorf("create array: %v != %v", val, 17)
	}
}

func Test_ArraysThree(t *testing.T) {
	json1 := New(nil)

	test, err := json1.ArrayOfSizeKey(1, "test1.test2")
	if err != nil {
		t.Fatal(err)
	}

	test.SetIndex(10, 0)
	if val := json1.Sub("test1.test2").Index(0).Value().(int); val != 10 {
		t.Error(err)
	}

	// ========

	obj2 := New(arrData)
	if val := obj2.Sub("b.ddd").Index(0).Value().(int64); val != int64(22) {
		t.Error(err)
	}

	oo := obj2.Sub("b.ddd")

	oo, err = oo.SetIndex(1000, 2)
	if err != nil {
		t.Error(err)
	}

	if val := oo.Index(2).Value().(int64); val != 1000 {
		t.Error(err)
	}
}

func Test_BadIndexes(t *testing.T) {
	jsonObj, err := ParseJSON([]byte(`{"array":[1,2,3]}`))
	if err != nil {
		t.Error(err)
	}

	if act := jsonObj.Index(0).Value(); act != nil {
		t.Errorf("Unexpected value returned: %v != %v", nil, act)
	}

	if act := jsonObj.Sub("array").Index(4).Value(); act != nil {
		t.Errorf("Unexpected value returned: %v != %v", nil, act)
	}

	// ========

	obj2 := New(arrData)
	if act := obj2.Sub("b.ddd").Index(4).Value(); act != nil {
		t.Errorf("Unexpected value returned: %v != %v", nil, act)
	}
	if act := obj2.Sub("b.hhTy66.777").Index(4).Value(); act != nil {
		t.Errorf("Unexpected value returned: %v != %v", nil, act)
	}

	oo := obj2.Sub("b.ddd")

	_, err = oo.SetIndex(1000, 4)
	if err != ErrOutOfBounds {
		t.Error("SetIndex error need ErrOutOfBounds")
	}
}

func Test_Deletes(t *testing.T) {
	jsonParsed, _ := ParseJSON([]byte(`{
		"outter":{
			"inner":{
				"value1":10,
				"value2":22,
				"value3":32
			},
			"alsoInner":{
				"value1":20,
				"value2":42,
				"value3":92
			},
			"another":{
				"value1":null,
				"value2":null,
				"value3":null
			}
		}
	}`))

	if err := jsonParsed.Delete("outter", "inner", "value2"); err != nil {
		t.Error(err)
	}
	if err := jsonParsed.Delete("outter", "inner", "value4"); err == nil {
		t.Error("value4 should not have been found in outter.inner")
	}
	if err := jsonParsed.Delete("outter", "another", "value1"); err != nil {
		t.Error(err)
	}
	if err := jsonParsed.Delete("outter", "another", "value4"); err == nil {
		t.Error("value4 should not have been found in outter.another")
	}
	if err := jsonParsed.DeleteKey("outter.alsoInner.value1"); err != nil {
		t.Error(err)
	}
	if err := jsonParsed.DeleteKey("outter.alsoInner.value4"); err == nil {
		t.Error("value4 should not have been found in outter.alsoInner")
	}
	if err := jsonParsed.DeleteKey("outter.another.value2"); err != nil {
		t.Error(err)
	}
	if err := jsonParsed.Delete("outter.another.value4"); err == nil {
		t.Error("value4 should not have been found in outter.another")
	}

	if err := jsonParsed.Delete(); err == nil {
		t.Error("value should not have been found in null")
	}

	expected := `{"outter":{"alsoInner":{"value2":42,"value3":92},"another":{"value3":null},"inner":{"value1":10,"value3":32}}}`
	if actual := jsonParsed.String(); actual != expected {
		t.Errorf("Unexpected result from deletes: %v != %v", actual, expected)
	}

	arrData2 := map[string]any{
		"a": 123,
		"b": map[string]any{
			"ff": map[any]any{
				111: "fccccc",
				222: "fddddd",
				333: "dfffff",
			},
			"t666": []float64{
				12.3,
				32.5,
				22.56,
				789.156,
			},
		},
	}

	jsonParsed2 := New(arrData2)
	if err := jsonParsed2.Delete("b", "ff", 333); err != nil {
		t.Error(err)
	}
	if err := jsonParsed2.Delete("b", "ff", 33355); err == nil {
		t.Error("data should not have been found in b.ff")
	}

	if err := jsonParsed2.Delete("b", "t666", 2); err != nil {
		t.Error(err)
	}
	if err := jsonParsed2.Delete("b", "t666", 7); err == nil {
		t.Error("data should not have been found in b.t666")
	}

	expected2 := `{"111":"fccccc","222":"fddddd"}`
	if actual2 := jsonParsed2.Sub("b.ff").String(); actual2 != expected2 {
		t.Errorf("Unexpected result from deletes: %v != %v", actual2, expected2)
	}

	expected2 = `[12.3,32.5,789.156]`
	if actual2 := jsonParsed2.Sub("b.t666").String(); actual2 != expected2 {
		t.Errorf("Unexpected result from deletes: %v != %v", actual2, expected2)
	}

	jsonParsed3 := New(nil)
	if err := jsonParsed3.Delete("b", "ff", 333); err == nil {
		t.Error("data should return error")
	}
}

func Test_DeletesWithSlices(t *testing.T) {
	rawJSON := `{
		"outter":[
			{
				"foo":{
					"value1":10,
					"value2":22,
					"value3":32
				},
				"bar": [
					20,
					42,
					92
				]
			},
			{
				"baz":{
					"value1":null,
					"value2":null,
					"value3":null
				}
			}
		]
	}`

	jsonParsed, err := ParseJSON([]byte(rawJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err = jsonParsed.Delete("outter", "1", "baz", "value1"); err != nil {
		t.Error(err)
	}

	expected := `{"outter":[{"bar":[20,42,92],"foo":{"value1":10,"value2":22,"value3":32}},{"baz":{"value2":null,"value3":null}}]}`
	if actual := jsonParsed.String(); actual != expected {
		t.Errorf("Unexpected result from array deletes: %v != %v", actual, expected)
	}

	jsonParsed, err = ParseJSON([]byte(rawJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err = jsonParsed.Delete("outter", "1", "baz"); err != nil {
		t.Error(err)
	}

	expected = `{"outter":[{"bar":[20,42,92],"foo":{"value1":10,"value2":22,"value3":32}},{}]}`
	if actual := jsonParsed.String(); actual != expected {
		t.Errorf("Unexpected result from array deletes: %v != %v", actual, expected)
	}

	jsonParsed, err = ParseJSON([]byte(rawJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err = jsonParsed.Delete("outter", "1"); err != nil {
		t.Error(err)
	}

	expected = `{"outter":[{"bar":[20,42,92],"foo":{"value1":10,"value2":22,"value3":32}}]}`
	if actual := jsonParsed.String(); actual != expected {
		t.Errorf("Unexpected result from array deletes: %v != %v", actual, expected)
	}

	jsonParsed, err = ParseJSON([]byte(rawJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err = jsonParsed.Delete("outter", "0", "bar", "0"); err != nil {
		t.Error(err)
	}

	expected = `{"outter":[{"bar":[42,92],"foo":{"value1":10,"value2":22,"value3":32}},{"baz":{"value1":null,"value2":null,"value3":null}}]}`
	if actual := jsonParsed.String(); actual != expected {
		t.Errorf("Unexpected result from array deletes: %v != %v", actual, expected)
	}

	jsonParsed, err = ParseJSON([]byte(rawJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err = jsonParsed.Delete("outter", "0", "bar", "1"); err != nil {
		t.Error(err)
	}

	expected = `{"outter":[{"bar":[20,92],"foo":{"value1":10,"value2":22,"value3":32}},{"baz":{"value1":null,"value2":null,"value3":null}}]}`
	if actual := jsonParsed.String(); actual != expected {
		t.Errorf("Unexpected result from array deletes: %v != %v", actual, expected)
	}

	jsonParsed, err = ParseJSON([]byte(rawJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err = jsonParsed.Delete("outter", "0", "bar", "2"); err != nil {
		t.Error(err)
	}

	expected = `{"outter":[{"bar":[20,42],"foo":{"value1":10,"value2":22,"value3":32}},{"baz":{"value1":null,"value2":null,"value3":null}}]}`
	if actual := jsonParsed.String(); actual != expected {
		t.Errorf("Unexpected result from array deletes: %v != %v", actual, expected)
	}
}

func Test_BasicWithDecoder(t *testing.T) {
	sample := []byte(`{"test":{"int":10, "float":6.66}}`)
	dec := json.NewDecoder(bytes.NewReader(sample))
	dec.UseNumber()

	val, err := ParseJSONDecoder(dec)
	if err != nil {
		t.Errorf("Failed to parse: %v", err)
		return
	}

	checkNumber := func(path string, expectedVal json.Number) {
		data := val.Sub(path).Value()
		asNumber, isNumber := data.(json.Number)
		if !isNumber {
			t.Error("Failed to parse using decoder UseNumber policy")
		}
		if expectedVal != asNumber {
			t.Errorf("Expected[%s] but got [%s]", expectedVal, asNumber)
		}
	}

	checkNumber("test.int", "10")
	checkNumber("test.float", "6.66")
}

func Test_BadWithDecoder(t *testing.T) {
	sample := []byte(`{"test":{"int":10, "float":6.66}`)
	dec := json.NewDecoder(bytes.NewReader(sample))
	dec.UseNumber()

	_, err := ParseJSONDecoder(dec)
	if err == nil {
		t.Error("data should not have been found in ParseJSONDecoder")
	}
}

func Test_isPathShadowedInDeepMap(t *testing.T) {
	assert := assertT(t)

	testData := []struct {
		key      string
		expected string
		msg      string
	}{
		{
			"a",
			"",
			"map[string]any",
		},
		{
			"b.dd.1",
			"b.dd",
			"[]any",
		},
		{
			"b.ff",
			"",
			"map[any]any",
		},
		{
			"b.hhTy3.222",
			"b.hhTy3",
			"&map[int]any",
		},
		{
			"b.hhTy3.333.qq2",
			"b.hhTy3",
			"map[any]string",
		},
		{
			"b.hhTy3.666.3",
			"b.hhTy3",
			"Slice",
		},
	}

	for _, v := range testData {
		check := New(nil).isPathShadowedInDeepMap(strings.Split(v.key, "."), arrData)

		assert(check, v.expected, v.msg)
	}

}

func Test_Example(t *testing.T) {
	assert := assertDeepEqualT(t)

	arrData := map[string]any{
		"a": 123,
		"b": map[string]any{
			"c": "ccc",
			"d": map[string]any{
				"e": "eee",
				"f": map[string]any{
					"g": "ggg",
				},
			},
			"dd": []any{
				"ccccc",
				"ddddd",
				"fffff",
			},
			"ff": map[any]any{
				111: "fccccc",
				222: "fddddd",
				333: "dfffff",
			},
			"hh": map[int]any{
				1115: "hccccc",
				2225: "hddddd",
				3335: map[any]string{
					"qq1": "qq1ccccc",
					"qq2": "qq2ddddd",
					"qq3": "qq3fffff",
				},
			},
			"kJh21ay": map[string]any{
				"Hjk2": "fccDcc",
				"23rt": "^hgcF5c",
			},
		},
	}

	{
		var res bool = New(arrData).Exists("b.kJh21ay.Hjk2")
		assert(true, res, "Exists")
	}
	{
		var res bool = New(arrData).Exists("b.kJh21ay.Hjk12")
		assert(false, res, "Exists")
	}

	{
		var res any = New(arrData).Get("b.kJh21ay.Hjk2")
		assert("fccDcc", res, "Get")
	}
	{
		var res any = New(arrData).Get("b.kJh21ay.Hjk12", "defVal")
		assert("defVal", res, "Get")
	}

	{
		var res any = New(arrData).Find("b.kJh21ay.Hjk2")
		assert("fccDcc", res, "Find")
	}
	{
		var res any = New(arrData).Find("b.kJh21ay.Hjk12")
		assert(nil, res, "Find")
	}

	{
		var res any = New(arrData).Sub("b.kJh21ay.Hjk2").Value()
		assert("fccDcc", res, "Sub")
	}
	{
		var res any = New(arrData).Sub("b.kJh21ay.Hjk12").Value()
		assert(nil, res, "Sub")
	}

	{
		var res any = New(arrData).Search("b", "kJh21ay", "Hjk2").Value()
		assert("fccDcc", res, "Search")
	}
	{
		var res any = New(arrData).Search("b", "kJh21ay", "Hjk12").Value()
		assert(nil, res, "Search")
	}

	{
		var res any = New(arrData).Sub("b.dd").Index(1).Value()
		assert("ddddd", res, "Index")
	}
	{
		var res any = New(arrData).Sub("b.dd").Index(6).Value()
		assert(nil, res, "Index")
	}

	{
		arr := New(arrData)
		arr.Set("qqqyyy", "b", "ff", 222)

		var res any = arr.Sub("b.ff.222").Value()
		assert("qqqyyy", res, "Set")
	}

	{
		arr := New(arrData)
		arr.Sub("b.dd").SetIndex("qqqyyySetIndex", 1)

		var res any = arr.Sub("b.dd.1").Value()
		assert("qqqyyySetIndex", res, "SetIndex")
	}

	{
		arr := New(arrData)

		var res0 any = arr.Sub("b.hh.2225").Value()
		assert("hddddd", res0, "Delete")

		err := arr.Delete("b", "hh", 2225)
		if err != nil {
			t.Error(err.Error())
		}

		var res any = arr.Sub("b.hh.2225").Value()
		assert(nil, res, "Delete")
	}

	{
		arr := New(arrData)

		var res0 any = arr.Sub("b.d.e").Value()
		assert("eee", res0, "DeleteKey")

		err := arr.DeleteKey("b.d.e")
		if err != nil {
			t.Error(err.Error())
		}

		var res any = arr.Sub("b.d.e").Value()
		assert(nil, res, "DeleteKey")
	}

}

func Example() {
	Get(arrData, "b.hhTy3.666.3")
}
