package encoding

import (
    "encoding/asn1"
)

// Asn1 Encode
func (this Encoding) Asn1Encode(data any) Encoding {
    this.data, this.Error = asn1.Marshal(data)

    return this
}

// Asn1 Decode
func (this Encoding) Asn1Decode(val any) Encoding {
    this.data, this.Error = asn1.Unmarshal(this.data, val)

    return this
}

// =============

// Asn1 Encode
func (this Encoding) Asn1EncodeWithParams(data any, params string) Encoding {
    this.data, this.Error = asn1.MarshalWithParams(data, params)

    return this
}

// Asn1 Decode
func (this Encoding) Asn1DecodeWithParams(val any, params string) Encoding {
    this.data, this.Error = asn1.UnmarshalWithParams(this.data, val, params)

    return this
}
