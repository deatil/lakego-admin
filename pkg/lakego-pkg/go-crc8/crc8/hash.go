package crc8

import "hash"

// crc8 hash
type Hash8 interface {
    hash.Hash
    Sum8() uint8
}

// 大小
const Size = 2

type digest struct {
    sum   uint8
    table *Table
}

// Write
func (this *digest) Write(data []byte) (int, error) {
    this.sum = this.table.Update(this.sum, data)

    return len(data), nil
}

// Sum
func (this *digest) Sum(b []byte) []byte {
    s := this.Sum8()
    return append(b, byte(s))
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

// Sum8
func (this *digest) Sum8() uint8 {
    return this.table.Complete(this.sum)
}

// 构造函数
func NewHash(table *Table) Hash8 {
    h := &digest{
        table: table,
    }
    h.Reset()

    return h
}
