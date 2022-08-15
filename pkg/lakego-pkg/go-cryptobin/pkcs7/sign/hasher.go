package sign

import (
    "hash"
    "encoding/asn1"
)

// hash
type SignHashWithFunc struct {
    // hash 摘要
    hashFunc   func() hash.Hash
    identifier asn1.ObjectIdentifier
}

// oid
func (this SignHashWithFunc) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 值大小
func (this SignHashWithFunc) Sum(data []byte) []byte {
    h := this.hashFunc()
    h.Write(data)
    newData := h.Sum(nil)

    return newData
}
