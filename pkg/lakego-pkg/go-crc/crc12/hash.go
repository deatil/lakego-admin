package crc12

import "hash"

// hash
type Hash12 interface {
    hash.Hash
    Sum12() uint16
}

// 大小
const Size = 2

type digest struct {
    sum   uint16
    table *Table
}

// Write
func (this *digest) Write(data []byte) (int, error) {
    this.sum = this.table.Update(this.sum, data)

    return len(data), nil
}

// Sum
func (this *digest) Sum(b []byte) []byte {
    s := this.Sum12()

    return append(b, byte(s>>8), byte(s))
}

// Reset
func (this *digest) Reset() {
    this.sum = this.table.params.Init
}

// Size
func (this *digest) Size() int {
    return Size
}

// BlockSize
func (this *digest) BlockSize() int {
    return 1
}

// Sum12
func (this *digest) Sum12() uint16 {
    return this.table.Complete(this.sum)
}

// 构造函数
func NewHash(table *Table) Hash12 {
    h := &digest{
        table: table,
    }
    h.Reset()

    return h
}
