//go:build (amd64 || arm64) && !purego && !gccgo
// +build amd64 arm64
// +build !purego
// +build !gccgo

package memory

import (
    "reflect"
    "unsafe"
)

func Memclr(b []byte) {
    if len(b) == 0 {
        return
    }
    memclrNoHeapPointers(unsafe.Pointer(&b[0]), uintptr(len(b)))
}

func MemclrU32(b []uint32) {
    if len(b) == 0 {
        return
    }
    memclrNoHeapPointers(unsafe.Pointer(&b[0]), uintptr(len(b)*4))
}

func MemclrU64(b []uint64) {
    if len(b) == 0 {
        return
    }
    memclrNoHeapPointers(unsafe.Pointer(&b[0]), uintptr(len(b)*8))
}

func MemclrI(v interface{}) {
    p := reflect.ValueOf(v)
    for p.Kind() == reflect.Ptr {
        p = p.Elem()
    }
    pt := p.Type()

    switch p.Kind() {
    case reflect.Slice:
        if sz := p.Cap(); sz > 0 {
            memclrNoHeapPointers(unsafe.Pointer(p.Pointer()), uintptr(sz)*pt.Elem().Size())
        }
    case reflect.Array:
        if sz := p.Cap(); sz > 0 {
            memclrNoHeapPointers(unsafe.Pointer(p.UnsafeAddr()), uintptr(sz)*pt.Elem().Size())
        }

    case reflect.Map:
        for _, key := range p.MapKeys() {
            p.SetMapIndex(key, reflect.Value{})
        }

    case reflect.Struct:
        memclrNoHeapPointers(unsafe.Pointer(p.UnsafeAddr()), pt.Size())
    }
}

//go:noescape
//go:linkname memclrNoHeapPointers runtime.memclrNoHeapPointers
func memclrNoHeapPointers(ptr unsafe.Pointer, n uintptr)
