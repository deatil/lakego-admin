package array

import (
    "math"
    "math/rand"
    "time"
    "bytes"
    "reflect"

    "github.com/deatil/lakego-doak/lakego/constraints"
)

// ArrayFill
func ArrayFill(startIndex int, num uint, value any) map[int]any {
    m := make(map[int]any)
    var i uint
    for i = 0; i < num; i++ {
        m[startIndex] = value
        startIndex++
    }

    return m
}

// ArrayFlip
func ArrayFlip(m map[any]any) map[any]any {
    n := make(map[any]any)
    for i, v := range m {
        n[v] = i
    }

    return n
}

// ArrayKeys
func ArrayKeys(elements map[any]any) []any {
    i, keys := 0, make([]any, len(elements))
    for key := range elements {
        keys[i] = key
        i++
    }

    return keys
}

// ArrayValues
func ArrayValues(elements map[any]any) []any {
    i, vals := 0, make([]any, len(elements))
    for _, val := range elements {
        vals[i] = val
        i++
    }

    return vals
}

// ArrayMerge
func ArrayMerge(ss ...[]any) []any {
    n := 0
    for _, v := range ss {
        n += len(v)
    }

    s := make([]any, 0, n)
    for _, v := range ss {
        s = append(s, v...)
    }

    return s
}

// ArrayChunk
func ArrayChunk(s []any, size int) [][]any {
    if size < 1 {
        return [][]any{}
    }

    length := len(s)
    chunks := int(math.Ceil(float64(length) / float64(size)))
    var n [][]any
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
func ArrayPad(s []any, size int, val any) []any {
    if size == 0 || (size > 0 && size < len(s)) || (size < 0 && size > -len(s)) {
        return s
    }

    n := size
    if size < 0 {
        n = -size
    }

    n -= len(s)
    tmp := make([]any, n)
    for i := 0; i < n; i++ {
        tmp[i] = val
    }

    if size > 0 {
        return append(s, tmp...)
    }

    return append(tmp, s...)
}

// ArraySlice
func ArraySlice(s []any, offset, length uint) []any {
    if offset > uint(len(s)) {
        return []any{}
    }

    end := offset + length
    if end < uint(len(s)) {
        return s[offset:end]
    }

    return s[offset:]
}

// ArrayRand
func ArrayRand(elements []any) []any {
    r := rand.New(rand.NewSource(time.Now().UnixNano()))
    n := make([]any, len(elements))

    for i, v := range r.Perm(len(elements)) {
        n[i] = elements[v]
    }

    return n
}

// ArrayColumn
func ArrayColumn(input map[string]map[string]any, columnKey string) []any {
    columns := make([]any, 0, len(input))
    for _, val := range input {
        if v, ok := val[columnKey]; ok {
            columns = append(columns, v)
        }
    }

    return columns
}

// ArrayPush
func ArrayPush(s *[]any, elements ...any) int {
    *s = append(*s, elements...)

    return len(*s)
}

// ArrayPop
func ArrayPop(s *[]any) any {
    if len(*s) == 0 {
        return nil
    }

    ep := len(*s) - 1
    e := (*s)[ep]
    *s = (*s)[:ep]

    return e
}

// ArrayUnshift
func ArrayUnshift(s *[]any, elements ...any) int {
    *s = append(elements, *s...)

    return len(*s)
}

// ArrayShift
func ArrayShift(s *[]any) any {
    if len(*s) == 0 {
        return nil
    }

    f := (*s)[0]
    *s = (*s)[1:]

    return f
}

// ArrayKeyExists
func ArrayKeyExists(key any, m map[any]any) bool {
    _, ok := m[key]

    return ok
}

// ArrayCombine
func ArrayCombine(s1, s2 []any) map[any]any {
    if len(s1) != len(s2) {
        return map[any]any{}
    }

    m := make(map[any]any, len(s1))
    for i, v := range s1 {
        m[v] = s2[i]
    }

    return m
}

// ArrayReverse
func ArrayReverse(s []any) []any {
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
func InArray(needle any, haystack any) bool {
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

func ArrayDiff[T constraints.Ordered](listA []T, listB []T) []T {
    tmp := make(map[T]struct{}, len(listA))
    var diffs []T

    for _, ka := range listA {
        tmp[ka] = struct{}{}
    }

    for _, kb := range listB {
        if _, ok := tmp[kb]; !ok {
            diffs = append(diffs, kb)
        }
    }

    return diffs
}
