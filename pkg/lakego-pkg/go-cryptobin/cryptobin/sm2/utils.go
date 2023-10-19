package sm2

// 格式化公钥压缩前缀
func formatPublicKeyCompressPrefix(p string) string {
    if p == "00" {
        return "02"
    }

    return "03"
}

// 格式化来源公钥压缩前缀
func formatFromPublicKeyCompressPrefix(p string) string {
    if p == "00" || p == "01" {
        return p
    }

    if p == "02" {
        return "00"
    }

    return "01"
}
