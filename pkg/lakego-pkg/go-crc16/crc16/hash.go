package crc16

import "hash"

// crc16 hash
type Hash16 interface {
    hash.Hash
    Sum16() uint16
}

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
    s := this.Sum16()
    return append(b, byte(s>>8), byte(s))
}

// Reset
func (this *digest) Reset() {
    this.sum = this.table.params.Init
}

// Size
func (this *digest) Size() int {
    return 2
}

// BlockSize
func (this *digest) BlockSize() int {
    return 1
}

// Sum16
func (this *digest) Sum16() uint16 {
    return this.table.Complete(this.sum)
}

// 构造函数
func NewHash(table *Table) Hash16 {
    h := &digest{
        table: table,
    }
    h.Reset()

    return h
}
