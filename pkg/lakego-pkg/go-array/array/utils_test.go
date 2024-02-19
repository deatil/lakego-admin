package array

import (
	"encoding/json"
	"fmt"
	"html/template"
	"testing"
)

func Test_ToString(t *testing.T) {
	assert := assertDeepEqualT(t)

	var jn json.Number
	_ = json.Unmarshal([]byte("8"), &jn)
	type Key struct {
		k string
	}
	key := &Key{"foo"}

	tests := []struct {
		input  any
		expect string
	}{
		{int(8), "8"},
		{int8(8), "8"},
		{int16(8), "8"},
		{int32(8), "8"},
		{int64(8), "8"},
		{uint(8), "8"},
		{uint8(8), "8"},
		{uint16(8), "8"},
		{uint32(8), "8"},
		{uint64(8), "8"},
		{float32(8.31), "8.31"},
		{float64(8.31), "8.31"},
		{jn, "8"},
		{true, "true"},
		{false, "false"},
		{nil, ""},
		{[]byte("one time"), "one time"},
		{"one more time", "one more time"},
		{template.HTML("one time"), "one time"},
		{template.URL("http://somehost.foo"), "http://somehost.foo"},
		{template.JS("(1+2)"), "(1+2)"},
		{template.CSS("a"), "a"},
		{template.HTMLAttr("a"), "a"},
		// errors
		{testing.T{}, ""},
		{key, ""},
	}

	for i, test := range tests {
		errmsg := fmt.Sprintf("i = %d", i)

		v := toString(test.input)

		assert(v, test.expect, errmsg)
	}
}

func Test_ToStringMap(t *testing.T) {
	assert := assertDeepEqualT(t)

	tests := []struct {
		input  any
		expect map[string]any
	}{
		{map[any]any{"tag": "tags", "group": "groups"}, map[string]any{"tag": "tags", "group": "groups"}},
		{map[string]any{"tag": "tags", "group": "groups"}, map[string]any{"tag": "tags", "group": "groups"}},
		{`{"tag": "tags", "group": "groups"}`, map[string]any{"tag": "tags", "group": "groups"}},
		{`{"tag": "tags", "group": true}`, map[string]any{"tag": "tags", "group": true}},

		// errors
		{nil, map[string]any{}},
		{testing.T{}, map[string]any{}},
		{"", map[string]any{}},
	}

	for i, test := range tests {
		errmsg := fmt.Sprintf("i = %d", i)

		v := toStringMap(test.input)

		assert(v, test.expect, errmsg)
	}
}
