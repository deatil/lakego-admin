package encoding

import (
    "encoding/json"

    jsoniter "github.com/json-iterator/go"
)

// JSON Encode
func (this Encoding) JSONEncode(data any) Encoding {
    this.data, this.Error = json.Marshal(data)

    return this
}

// JSON Decode
func (this Encoding) JSONDecode(dst any) Encoding {
    this.Error = json.Unmarshal(this.data, dst)

    return this
}

// ====================

// JSONIterator Encode
func (this Encoding) JSONIteratorEncode(data any) Encoding {
    this.data, this.Error = jsoniter.Marshal(data)

    return this
}

// JSONIterator Indent Encode
func (this Encoding) JSONIteratorIndentEncode(v any, prefix, indent string) Encoding {
    this.data, this.Error = jsoniter.MarshalIndent(v, prefix, indent)

    return this
}

// JSONIterator Decode
func (this Encoding) JSONIteratorDecode(dst any) Encoding {
    this.Error = jsoniter.Unmarshal(this.data, dst)

    return this
}
