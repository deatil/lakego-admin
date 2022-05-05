package pipeline

type (
    // 迭代的值
    ArrayItem = any

    // 回调函数
    CallableFunc = func(any, ArrayItem) any
)

// 用回调函数迭代地将数组简化为单一的值
func ArrayReduce(array []ArrayItem, callback CallableFunc, initial any) ArrayItem {
    data := initial

    if len(array) > 0 {
        for _, item := range array {
            data = callback(data, item)
        }
    }

    return data
}

// 数组翻转
func ArrayReverse(s []any) []any {
    for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
        s[i], s[j] = s[j], s[i]
    }

    return s
}
