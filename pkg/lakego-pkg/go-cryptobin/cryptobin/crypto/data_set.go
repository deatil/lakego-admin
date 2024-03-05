package crypto

import (
    "sync"
)

// DataName interface
type DataName interface {
    ~uint | ~int | ~string
}

/**
 * 数据设置 / Data Set
 *
 * @create 2023-3-31
 * @author deatil
 */
type DataSet[N DataName, M any] struct {
    // 读写锁 / RWMutex
    mu sync.RWMutex

    // 数据 / data
    data map[N]func() M
}

// 构造函数
// New DataSet
func NewDataSet[N DataName, M any]() *DataSet[N, M] {
    return &DataSet[N, M]{
        data: make(map[N]func() M),
    }
}

// 设置
// add data
func (this *DataSet[N, M]) Add(name N, data func() M) *DataSet[N, M] {
    this.mu.Lock()
    defer this.mu.Unlock()

    this.data[name] = data

    return this
}

// 判断是否有数据
// exists data by name
func (this *DataSet[N, M]) Has(name N) bool {
    this.mu.RLock()
    defer this.mu.RUnlock()

    if _, ok := this.data[name]; ok {
        return true
    }

    return false
}

// 获取数据
// get data by name
func (this *DataSet[N, M]) Get(name N) func() M {
    this.mu.RLock()
    defer this.mu.RUnlock()

    if data, ok := this.data[name]; ok {
        return data
    }

    return nil
}

// 删除数据
// remove data by name
func (this *DataSet[N, M]) Remove(name N) *DataSet[N, M] {
    this.mu.Lock()
    defer this.mu.Unlock()

    delete(this.data, name)

    return this
}

// 数据名称列表
// name list
func (this *DataSet[N, M]) Names() []N {
    this.mu.RLock()
    defer this.mu.RUnlock()

    names := make([]N, 0)
    for name, _ := range this.data {
        names = append(names, name)
    }

    return names
}

// 获取所有数据
// get all data
func (this *DataSet[N, M]) All() map[N]func() M {
    return this.data
}

// 清空数据
// clear data
func (this *DataSet[N, M]) Clean() {
    this.mu.Lock()
    defer this.mu.Unlock()

    for name, _ := range this.data {
        delete(this.data, name)
    }
}

// 获取数据长度
// get data len
func (this *DataSet[N, M]) Len() int {
    return len(this.data)
}
