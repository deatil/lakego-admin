package assert

// 条件断言
func Assert(condition bool, message string) {
    if !condition {
        panic("Error#" + message)
    }
}

// 断言
func AssertIf[T any](condition bool, trueData T, falseData T) T {
    if condition {
        return trueData
    }

    return falseData
}
