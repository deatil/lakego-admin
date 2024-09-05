package kcdsa

import (
    "hash"
)

type ppgfCtx struct {
    h           hash.Hash
    initSources [][]byte

    lh int
}

func ppgf(
    dst []byte,
    nBits int, h hash.Hash, src ...[]byte,
) []byte {
    return newPPGF(h).Generate(dst, nBits, src...)
}

func newPPGF(h hash.Hash, src ...[]byte) (ppgf ppgfCtx) {
    ppgf.h = h
    ppgf.initSources = src

    ppgf.lh = h.Size()
    return
}

func (p ppgfCtx) Generate(dst []byte, nBits int, src ...[]byte) []byte {
    i := bitsToBytes(nBits)
    dst = Grow(dst, i)

    var iBuf [1]byte
    hbuf := make([]byte, 0, p.lh)

    for {
        p.h.Reset()
        for _, v := range p.initSources {
            p.h.Write(v)
        }

        for _, v := range src {
            p.h.Write(v)
        }

        p.h.Write(iBuf[:])
        hbuf = p.h.Sum(hbuf[:0])

        if i >= p.lh {
            i -= p.lh
            copy(dst[i:], hbuf)
            if i == 0 {
                break
            }
        } else {
            copy(dst, hbuf[len(hbuf)-i:])
            break
        }

        iBuf[0]++
    }

    return RightMost(dst, nBits)
}
