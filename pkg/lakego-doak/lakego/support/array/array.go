package array

import (
    "math"
    "math/rand"
    "time"
    "bytes"
    "reflect"
)

// ArrayFill
func ArrayFill(startIndex int, num uint, value interface{}) map[int]interface{} {
    m := make(map[int]interface{})
    var i uint
    for i = 0; i < num; i++ {
        m[startIndex] = value
        startIndex++
    }

    return m
}

// ArrayFlip
func ArrayFlip(m map[interface{}]interface{}) map[interface{}]interface{} {
    n := make(map[interface{}]interface{})
    for i, v := range m {
        n[v] = i
    }

    return n
}

// ArrayKeys
func ArrayKeys(elements map[interface{}]interface{}) []interface{} {
    i, keys := 0, make([]interface{}, len(elements))
    for key := range elements {
        keys[i] = key
        i++
    }

    return keys
}

// ArrayValues
func ArrayValues(elements map[interface{}]interface{}) []interface{} {
    i, vals := 0, make([]interface{}, len(elements))
    for _, val := range elements {
        vals[i] = val
        i++
    }

    return vals
}

// ArrayMerge
func ArrayMerge(ss ...[]interface{}) []interface{} {
    n := 0
    for _, v := range ss {
        n += len(v)
    }

    s := make([]interface{}, 0, n)
    for _, v := range ss {
        s = append(s, v...)
    }

    return s
}

// ArrayChunk
func ArrayChunk(s []interface{}, size int) [][]interface{} {
    if size < 1 {
        return [][]interface{}{}
    }

    length := len(s)
    chunks := int(math.Ceil(float64(length) / float64(size)))
    var n [][]interface{}
    for i, end := 0, 0; chunks > 0; chunks-- {
        end = (i + 1) * size
        if end > length {
            end = length
        }

        n = append(n, s[i*size:end])
        i++
    }

    return n
}

// ArrayPa
func ArrayPad(s []interface{}, size int, val interface{}) []interface{} {
    if size == 0 || (size > 0 && size < len(s)) || (size < 0 && size > -len(s)) {
        return s
    }

    n := size
    if size < 0 {
        n = -size
    }

    n -= len(s)
    tmp := make([]interface{}, n)
    for i := 0; i < n; i++ {
        tmp[i] = val
    }

    if size > 0 {
        return append(s, tmp...)
    }

    return append(tmp, s...)
}

// ArraySlice
func ArraySlice(s []interface{}, offset, length uint) []interface{} {
    if offset > uint(len(s)) {
        return []interface{}{}
    }

    end := offset + length
    if end < uint(len(s)) {
        return s[offset:end]
    }

    return s[offset:]
}

// ArrayRand
func ArrayRand(elements []interface{}) []interface{} {
    r := rand.New(rand.NewSource(time.Now().UnixNano()))
    n := make([]interface{}, len(elements))

    for i, v := range r.Perm(len(elements)) {
        n[i] = elements[v]
    }

    return n
}

// ArrayColumn
func ArrayColumn(input map[string]map[string]interface{}, columnKey string) []interface{} {
    columns := make([]interface{}, 0, len(input))
    for _, val := range input {
        if v, ok := val[columnKey]; ok {
            columns = append(columns, v)
        }
    }

    return columns
}

// ArrayPush
func ArrayPush(s *[]interface{}, elements ...interface{}) int {
    *s = append(*s, elements...)

    return len(*s)
}

// ArrayPop
func ArrayPop(s *[]interface{}) interface{} {
    if len(*s) == 0 {
        return nil
    }

    ep := len(*s) - 1
    e := (*s)[ep]
    *s = (*s)[:ep]

    return e
}

// ArrayUnshift
func ArrayUnshift(s *[]interface{}, elements ...interface{}) int {
    *s = append(elements, *s...)

    return len(*s)
}

// ArrayShift
func ArrayShift(s *[]interface{}) interface{} {
    if len(*s) == 0 {
        return nil
    }

    f := (*s)[0]
    *s = (*s)[1:]

    return f
}

// ArrayKeyExists
func ArrayKeyExists(key interface{}, m map[interface{}]interface{}) bool {
    _, ok := m[key]

    return ok
}

// ArrayCombine
func ArrayCombine(s1, s2 []interface{}) map[interface{}]interface{} {
    if len(s1) != len(s2) {
        return map[interface{}]interface{}{}
    }

    m := make(map[interface{}]interface{}, len(s1))
    for i, v := range s1 {
        m[v] = s2[i]
    }

    return m
}

// ArrayReverse
func ArrayReverse(s []interface{}) []interface{} {
    for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
        s[i], s[j] = s[j], s[i]
    }

    return s
}

// Implode
func Implode(glue string, pieces []string) string {
    var buf bytes.Buffer
    l := len(pieces)

    for _, str := range pieces {
        buf.WriteString(str)
        if l--; l > 0 {
            buf.WriteString(glue)
        }
    }

    return buf.String()
}

// needle: string, haystack: []string.
func InArray(needle interface{}, haystack interface{}) bool {
    val := reflect.ValueOf(haystack)

    switch val.Kind() {
        case reflect.Slice, reflect.Array:
            for i := 0; i < val.Len(); i++ {
                if reflect.DeepEqual(needle, val.Index(i).Interface()) {
                    return true
                }
            }

        case reflect.Map:
            for _, k := range val.MapKeys() {
                if reflect.DeepEqual(needle, val.MapIndex(k).Interface()) {
                    return true
                }
            }

        default:
            return false
    }

    return false
}
