package encoding

import (
    "net/url"
)

// SafeURL Decode
func (this Encoding) SafeURLDecode() Encoding {
    data := string(this.data)
    dst, err := url.QueryUnescape(data)

    this.data  = []byte(dst)
    this.Error = err

    return this
}

// SafeURL Encode
func (this Encoding) SafeURLEncode() Encoding {
    data := url.QueryEscape(string(this.data))
    this.data = []byte(data)

    return this
}
