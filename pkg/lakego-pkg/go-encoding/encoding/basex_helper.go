package encoding

// 加密
func Base2Encode(str string) string {
    newStr := NewBasex("01").Encode([]byte(str))
    return newStr
}

// 解密
func Base2Decode(str string) string {
    newStr, err := NewBasex("01").Decode(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}

// =============================

// 加密
func Base16Encode(str string) string {
    newStr := NewBasex("0123456789abcdef").Encode([]byte(str))
    return newStr
}

// 解密
func Base16Decode(str string) string {
    newStr, err := NewBasex("0123456789abcdef").Decode(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}

// =============================

// 加密
func Base62Encode(str string) string {
    newStr := NewBasex("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ").Encode([]byte(str))
    return newStr
}

// 解密
func Base62Decode(str string) string {
    newStr, err := NewBasex("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ").Decode(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}
