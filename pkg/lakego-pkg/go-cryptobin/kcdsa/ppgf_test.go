package kcdsa

import (
    "bufio"
    "bytes"
    "crypto/rand"
    "crypto/sha256"
    "hash"
    "testing"
)

func TestPPGF(t *testing.T) {
    const iter = 4096
    const dstBit = 510 * 8

    rnd := bufio.NewReaderSize(rand.Reader, 1<<15)

    src1 := make([]byte, 1024)
    src2 := make([]byte, 1024)

    var dst1, dst2 []byte

    rnd.Read(src1)
    ppgf1 := newPPGF(&hashWrap{h: sha256.New()}, src1)
    ppgf2 := newPPGF(sha256.New(), src1)

    for i := 0; i < iter; i++ {
        rnd.Read(src2)
        dst1 = ppgf1.Generate(dst1[:0], dstBit, src2)
        dst2 = ppgf2.Generate(dst2[:0], dstBit, src2)

        if !bytes.Equal(dst1, dst2) {
            t.Errorf("ppgf1 != ppgf2")
            return
        }
    }
}

func BenchmarkPPGF(b *testing.B) {
    rnd := bufio.NewReaderSize(rand.Reader, 1<<15)

    bench := func(h hash.Hash) func(b *testing.B) {
        return func(b *testing.B) {
            dstBits := h.BlockSize()*h.BlockSize() + 3

            src1 := make([]byte, 1024)
            src2 := make([]byte, 1024)
            dst := make([]byte, dstBits)

            rnd.Read(src1)
            ppgf := newPPGF(h, src1)

            b.ReportAllocs()
            b.ResetTimer()
            b.SetBytes(int64(dstBits))
            for i := 0; i < b.N; i++ {
                rnd.Read(src2)
                dst = ppgf.Generate(dst[:0], dstBits, src2)
            }
        }
    }

    b.Run("Hash", bench(&hashWrap{h: sha256.New()}))
    b.Run("MarshalableHash", bench(sha256.New()))
}

type hashWrap struct {
    h hash.Hash
}

func (h *hashWrap) Write(p []byte) (int, error) { return h.h.Write(p) }
func (h *hashWrap) Sum(b []byte) []byte         { return h.h.Sum(b) }
func (h *hashWrap) Reset()                      { h.h.Reset() }
func (h *hashWrap) Size() int                   { return h.h.Size() }
func (h *hashWrap) BlockSize() int              { return h.h.BlockSize() }
