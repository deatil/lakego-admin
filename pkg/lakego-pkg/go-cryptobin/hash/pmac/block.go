package pmac

import (
    "crypto/cipher"
    "crypto/subtle"
)

const (
    // R is the minimal irreducible polynomial for a 128-bit block size
    R = 0x87
)

// Block is a 128-bit array used by certain block ciphers (i.e. AES)
type Block struct {
    Data []byte

    Size int
}

func NewBlock(size int) Block {
    return Block{
        Data: make([]byte, size),
        Size: size,
    }
}

// Clear zeroes out the contents of the block
func (b *Block) Clear() {
    for i := range b.Data {
        b.Data[i] = 0
    }
}

// Dbl performs a doubling of a block over GF(2^128):
//
//     a<<1 if firstbit(a)=0
//     (a<<1) ⊕ 0¹²⁰10000111 if firstbit(a)=1
//
func (b *Block) Dbl() {
    var z byte

    for i := b.Size - 1; i >= 0; i-- {
        zz := b.Data[i] >> 7
        b.Data[i] = b.Data[i]<<1 | z
        z = zz
    }

    b.Data[b.Size-1] ^= byte(subtle.ConstantTimeSelect(int(z), R, 0))
}

// Encrypt a block with the given block cipher
func (b *Block) Encrypt(c cipher.Block) {
    c.Encrypt(b.Data, b.Data)
}
