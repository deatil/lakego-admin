package crypto

import (
    "sync"
)

// 加密解密
var UseEncrypt = NewManger[Multiple, IEncrypt]()
// 模式
var UseMode = NewManger[Mode, IMode]()
// 补码
var UsePadding = NewManger[Padding, IPadding]()

// 构造函数
func NewManger[N MangerName, M any]() *Manger[N, M] {
    return &Manger[N, M]{
        data: make(map[N]func() M),
    }
}

type MangerName interface {
    Multiple | Mode | Padding
}

/**
 * 管理
 *
 * @create 2023-3-31
 * @author deatil
 */
type Manger[N MangerName, M any] struct {
    // 锁定
    mu sync.RWMutex

    // 数据
    data map[N]func() M
}

// 设置
func (this *Manger[N, M]) Add(name N, data func() M) *Manger[N, M] {
    this.mu.Lock()
    defer this.mu.Unlock()

    this.data[name] = data

    return this
}

func (this *Manger[N, M]) Has(name N) bool {
    this.mu.RLock()
    defer this.mu.RUnlock()

    if _, ok := this.data[name]; ok {
        return true
    }

    return false
}

func (this *Manger[N, M]) Get(name N) func() M {
    this.mu.RLock()
    defer this.mu.RUnlock()

    if data, ok := this.data[name]; ok {
        return data
    }

    return nil
}

// 删除
func (this *Manger[N, M]) Remove(name N) *Manger[N, M] {
    this.mu.Lock()
    defer this.mu.Unlock()

    delete(this.data, name)

    return this
}

func (this *Manger[N, M]) Names() []N {
    names := make([]N, 0)
    for name, _ := range this.data {
        names = append(names, name)
    }

    return names
}

func (this *Manger[N, M]) Len() int {
    return len(this.data)
}
