package encoding

import (
    "github.com/deatil/go-encoding/basex"
)

// 加密
func Base2Encode(str string) string {
    newStr := basex.Base2Encoding.Encode([]byte(str))
    return newStr
}

// 解密
func Base2Decode(str string) string {
    newStr, err := basex.Base2Encoding.Decode(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}

// =============================

// 加密
func Base16Encode(str string) string {
    newStr := basex.Base16Encoding.Encode([]byte(str))
    return newStr
}

// 解密
func Base16Decode(str string) string {
    newStr, err := basex.Base16Encoding.Decode(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}

// =============================

// 加密
func Base62Encode(str string) string {
    newStr := basex.Base62Encoding.Encode([]byte(str))
    return newStr
}

// 解密
func Base62Decode(str string) string {
    newStr, err := basex.Base62Encoding.Decode(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}
