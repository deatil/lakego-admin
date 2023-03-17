package encoding

import (
    "github.com/deatil/go-encoding/base62"
)

// Base62
func (this Encoding) Base62Decode() Encoding {
    data := string(this.data)
    this.data, this.Error = base62.StdEncoding.DecodeString(data)

    return this
}

// 编码 Base62
func (this Encoding) Base62Encode() Encoding {
    data := base62.StdEncoding.EncodeToString(this.data)
    this.data = []byte(data)

    return this
}
