package encoding

import (
    "io"
    "encoding/json"

    jsoniter "github.com/json-iterator/go"
)

// Json 编码
func JsonEncode(src any) string {
    data, _ := json.Marshal(src)

    return string(data)
}

// Json 解码
func JsonDecode(data string, dst any) error {
    return json.Unmarshal([]byte(data), dst)
}

// =======================

// Json 编码
func Marshal(v any) ([]byte, error) {
    return jsoniter.Marshal(v)
}

// Json 编码
func MarshalIndent(v any, prefix, indent string) ([]byte, error) {
    return jsoniter.MarshalIndent(v, prefix, indent)
}

// Json 解码
func Unmarshal(data []byte, v any) error {
    return jsoniter.Unmarshal(data, v)
}

func NewDecoder(r io.Reader) *jsoniter.Decoder {
    return jsoniter.NewDecoder(r)
}
