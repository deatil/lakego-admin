package crc16

import "hash"

// crc16 hash
type Hash16 interface {
    hash.Hash
    Sum16() uint16
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
    s := this.Sum16()

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

// Sum16
func (this *digest) Sum16() uint16 {
    return this.crc.Complete(this.sum)
}

// 构造函数
func NewHash(crc *CRC) Hash16 {
    h := &digest{
        crc: crc,
    }
    h.Reset()

    return h
}
