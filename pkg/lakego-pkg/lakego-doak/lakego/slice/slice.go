package slice

type Signed interface{
    ~int | ~int8 | ~int16 | ~int32 | ~int64
}

type Unsigned interface{
    ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64
}

type Float interface{
    ~float32 | ~float64
}

type Complex interface{
    ~complex64 | ~complex128
}

type Integer interface{
    Signed | Unsigned
}

type IntegerFloat interface{
    Integer | Float
}

type Ordered interface{
    Integer | Float | ~string
}

type MathInteger interface{
    Integer | Float | Complex
}

// 判断是否在数组里
func Contains[T Ordered](items []T, item T) bool {
    for _, v := range items {
        if v == item {
            return true
        }
    }

    return false
}

// 取最小值
func Min[T IntegerFloat](items ...T) T {
    min := items[0]
    for _, v := range items {
        if min > v {
            min = v
        }
    }

    return min
}

// 取最大值
func Max[T IntegerFloat](items ...T) T {
    max := items[0]
    for _, v := range items {
        if max < v {
            max = v
        }
    }

    return max
}

// 求和
func Sum[T MathInteger](s ...T) (sum T) {
    for _, v := range s {
        sum += v
    }

    return
}

// 合并
func Merge[T any](items ...[]T) (c []T) {
    for _, item := range items {
        c = append(c, item...)
    }

    return
}

// 排除相同数据
func Unique[T Ordered](s []T) []T {
    size := len(s)
    if size == 0 {
        return []T{}
    }

    m := make(map[T]struct{})
    for i := 0; i < size; i++ {
        m[s[i]] = struct{}{}
    }

    realLen := len(m)
    ret := make([]T, realLen)

    idx := 0
    for key := range m {
        ret[idx] = key
        idx++
    }

    return ret
}
