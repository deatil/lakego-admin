package crc32

import "hash"

// crc32 hash
type Hash32 interface {
    hash.Hash
    Sum32() uint32
}

// 大小
const Size = 4

type digest struct {
    sum uint32
    crc *CRC
}

// Write
func (this *digest) Write(data []byte) (int, error) {
    this.sum = this.crc.Update(this.sum, data)

    return len(data), nil
}

// Sum
func (this *digest) Sum(b []byte) []byte {
    s := this.Sum32()

    return append(b, byte(s>>24), byte(s>>16), byte(s>>8), byte(s))
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

// Sum32
func (this *digest) Sum32() uint32 {
    return this.crc.Complete(this.sum)
}

// 构造函数
func NewHash(crc *CRC) Hash32 {
    h := &digest{
        crc: crc,
    }
    h.Reset()

    return h
}
