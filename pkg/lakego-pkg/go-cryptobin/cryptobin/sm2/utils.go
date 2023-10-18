package sm2

// 获取前缀
func getPrefix(p string) string {
    if p == "00" {
        return "02"
    }

    return "03"
}

// 反向判断
func changePrefix(p string) string {
    if p == "02" {
        return "00"
    }

    return "01"
}
