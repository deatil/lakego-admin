package encoding

import (
    "net/url"
)

// SafeURL 加密
func SafeURLEncode(str string) string {
    return url.QueryEscape(str)
}

// SafeURL 解密
func SafeURLDecode(str string) string {
    dst, err := url.QueryUnescape(str)
    if err != nil {
        return ""
    }

    return dst
}

// ====================

// 对 URL 进行转义解码
func (this Encoding) FromSafeURL(data string) Encoding {
    dst, err := url.QueryUnescape(data)

    this.data  = []byte(dst)
    this.Error = err

    return this
}

// SafeURL
func FromSafeURL(data string) Encoding {
    return defaultEncode.FromSafeURL(data)
}

// 对 URL 进行转义编码
func (this Encoding) ToSafeURL() string {
    return url.QueryEscape(string(this.data))
}
