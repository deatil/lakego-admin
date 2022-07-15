package crc40

import "hash"

// hash
type Hash40 interface {
    hash.Hash
    Sum40() uint64
}

// 大小
const Size = 5

type digest struct {
    sum   uint64
    table *Table
}

// Write
func (this *digest) Write(data []byte) (int, error) {
    this.sum = this.table.Update(this.sum, data)

    return len(data), nil
}

// Sum
func (this *digest) Sum(b []byte) []byte {
    s := this.Sum40()

    return append(b, byte(s>>32), byte(s>>24), byte(s>>16), byte(s>>8), byte(s))
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

// Sum40
func (this *digest) Sum40() uint64 {
    return this.table.Complete(this.sum)
}

// 构造函数
func NewHash(table *Table) Hash40 {
    h := &digest{
        table: table,
    }
    h.Reset()

    return h
}
