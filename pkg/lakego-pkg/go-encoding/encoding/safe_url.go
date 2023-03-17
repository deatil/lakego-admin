package encoding

import (
    "net/url"
)

// 对 URL 进行转义解码
func (this Encoding) SafeURLDecode() Encoding {
    data := string(this.data)
    dst, err := url.QueryUnescape(data)

    this.data  = []byte(dst)
    this.Error = err

    return this
}

// 对 URL 进行转义编码
func (this Encoding) SafeURLEncode() Encoding {
    data := url.QueryEscape(string(this.data))
    this.data = []byte(data)

    return this
}
