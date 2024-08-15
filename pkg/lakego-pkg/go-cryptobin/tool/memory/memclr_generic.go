//go:build !((amd64 || arm64) && !purego && !gccgo)
// +build !amd64,!arm64 purego gccgo

package memory

import "reflect"

func Memclr(b []byte) {
    Memset(b, 0)
}

func MemclrU32(b []uint32) {
    MemsetU32(b, 0)
}

func MemclrU64(b []uint64) {
    MemsetU64(b, 0)
}

func MemclrI(v interface{}) {
    p := reflect.ValueOf(v)
    for p.Kind() == reflect.Ptr {
        p = p.Elem()
    }
    switch p.Kind() {
    case reflect.Slice:
        l := p.Len()
        for idx := 0; idx < l; idx++ {
            pidx := p.Index(idx)
            pidx.Set(reflect.Zero(pidx.Type()))
        }

    case reflect.Array:
        l := p.Len()
        for idx := 0; idx < l; idx++ {
            pidx := p.Index(idx)
            pidx.Set(reflect.Zero(pidx.Type()))
        }

    case reflect.Map:
        for _, key := range p.MapKeys() {
            p.SetMapIndex(key, reflect.Value{})
        }

    case reflect.Struct:
        p.Set(reflect.Zero(p.Type()))
    }
}
