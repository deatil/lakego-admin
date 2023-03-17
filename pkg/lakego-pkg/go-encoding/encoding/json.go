package encoding

import (
    "encoding/json"

    jsoniter "github.com/json-iterator/go"
)

// JSON
func (this Encoding) JSONEncode(data any) Encoding {
    this.data, this.Error = json.Marshal(data)

    return this
}

// JSON 编码输出
func (this Encoding) JSONDecode(dst any) Encoding {
    this.Error = json.Unmarshal(this.data, dst)

    return this
}

// ====================

// JSON
func (this Encoding) JSONIteratorEncode(data any) Encoding {
    this.data, this.Error = jsoniter.Marshal(data)

    return this
}

// JSON
func (this Encoding) JSONIteratorIndentEncode(v any, prefix, indent string) Encoding {
    this.data, this.Error = jsoniter.MarshalIndent(v, prefix, indent)

    return this
}

// JSON 编码输出
func (this Encoding) JSONIteratorDecode(dst any) Encoding {
    this.Error = jsoniter.Unmarshal(this.data, dst)

    return this
}
