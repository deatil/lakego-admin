package encoding

// 加密
func Base2Encode(str string) string {
    newStr := NewBasex(BasexBase2Key).Encode([]byte(str))
    return newStr
}

// 解密
func Base2Decode(str string) string {
    newStr, err := NewBasex(BasexBase2Key).Decode(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}

// =============================

// 加密
func Base16Encode(str string) string {
    newStr := NewBasex(BasexBase16Key).Encode([]byte(str))
    return newStr
}

// 解密
func Base16Decode(str string) string {
    newStr, err := NewBasex(BasexBase16Key).Decode(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}

// =============================

// 加密
func Base62Encode(str string) string {
    newStr := NewBasex(BasexBase62Key).Encode([]byte(str))
    return newStr
}

// 解密
func Base62Decode(str string) string {
    newStr, err := NewBasex(BasexBase62Key).Decode(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}
