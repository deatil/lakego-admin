package crc24

import "hash"

// hash
type Hash24 interface {
    hash.Hash
    Sum24() uint32
}

// 大小
const Size = 3

type digest struct {
    sum   uint32
    table *Table
}

// Write
func (this *digest) Write(data []byte) (int, error) {
    this.sum = this.table.Update(this.sum, data)

    return len(data), nil
}

// Sum
func (this *digest) Sum(b []byte) []byte {
    s := this.Sum24()

    return append(b, byte(s>>16), byte(s>>8), byte(s))
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

// Sum24
func (this *digest) Sum24() uint32 {
    return this.table.Complete(this.sum)
}

// 构造函数
func NewHash(table *Table) Hash24 {
    h := &digest{
        table: table,
    }
    h.Reset()

    return h
}
