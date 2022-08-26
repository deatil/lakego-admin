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
    sum uint16
    crc *CRC
}

// Write
func (this *digest) Write(data []byte) (int, error) {
    this.sum = this.crc.Update(this.sum, data)

    return len(data), nil
}

// Sum
func (this *digest) Sum(b []byte) []byte {
    s := this.Sum12()

    return append(b, byte(s>>8), byte(s))
}

// Reset
func (this *digest) Reset() {
    this.sum = this.crc.params.Init
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
    return this.crc.Complete(this.sum)
}

// 构造函数
func NewHash(crc *CRC) Hash12 {
    h := &digest{
        crc: crc,
    }
    h.Reset()

    return h
}
