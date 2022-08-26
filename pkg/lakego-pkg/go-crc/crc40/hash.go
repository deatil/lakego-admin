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
    sum uint64
    crc *CRC
}

// Write
func (this *digest) Write(data []byte) (int, error) {
    this.sum = this.crc.Update(this.sum, data)

    return len(data), nil
}

// Sum
func (this *digest) Sum(b []byte) []byte {
    s := this.Sum40()

    return append(b, byte(s>>32), byte(s>>24), byte(s>>16), byte(s>>8), byte(s))
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

// Sum40
func (this *digest) Sum40() uint64 {
    return this.crc.Complete(this.sum)
}

// 构造函数
func NewHash(crc *CRC) Hash40 {
    h := &digest{
        crc: crc,
    }
    h.Reset()

    return h
}
