package lms

import (
    "fmt"
    "sync"
)

// TypeDataName interface
type TypeDataName interface {
    ~uint32 | ~int
}

// TypeParams
type TypeParams[N TypeDataName, M any] struct {
    // RWMutex
    mu sync.RWMutex

    // datas
    data map[N]func() M
}

func NewTypeParams[N TypeDataName, M any]() *TypeParams[N, M] {
    return &TypeParams[N, M] {
        data: make(map[N]func() M),
    }
}

// AddParam
func (this *TypeParams[N, M]) AddParam(typ N, fn func() M) {
    this.mu.Lock()
    defer this.mu.Unlock()

    this.data[typ] = fn
}

// GetParam
func (this *TypeParams[N, M]) GetParam(typ N) (func() M, error) {
    this.mu.RLock()
    defer this.mu.RUnlock()

    param, ok := this.data[typ]
    if !ok {
        err := fmt.Errorf("lms: unsupported param (ID: %d)", typ)
        return nil, err
    }

    return param, nil
}

// AllParams
func (this *TypeParams[N, M]) AllParams() map[N]func() M {
    this.mu.RLock()
    defer this.mu.RUnlock()

    return this.data
}
