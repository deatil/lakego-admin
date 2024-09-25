// Pakcage gmac implements a Galois/Counter Mode (GCM) based MAC, as defined in KS X ISO/IEC 9797-3, NIST SP 800-38D.
package gmac

import (
    "hash"
    "errors"
    "crypto/cipher"

    "github.com/deatil/go-hash/gmac/gcm"
)

var (
    errBlockSize = errors.New("go-hash/gmac: requires 128-bit block cipher")
)

var defaultIV [gcm.GCMStandardNonceSize]byte

type ghash struct {
    gcm gcm.GCM

    tagMask [gcm.GCMBlockSize]byte

    y         gcm.GCMFieldElement
    remains   [gcm.GCMBlockSize]byte
    remainIdx int
    written   int
}

// new MAC using GMAC by only passing additional data(aad data).
func New(b cipher.Block, iv []byte) (hash.Hash, error) {
    kb := gcm.WrapCipher(b)

    if kb.BlockSize() != gcm.GCMBlockSize {
        return nil, errBlockSize
    }

    if len(iv) == 0 {
        iv = defaultIV[:]
    }

    g := new(ghash)
    g.gcm.Init(kb)

    var counter [gcm.GCMBlockSize]byte
    g.gcm.DeriveCounter(&counter, iv)
    kb.Encrypt(g.tagMask[:], counter[:])

    return g, nil
}

func (g ghash) Size() int {
    return gcm.GCMBlockSize
}

func (g ghash) BlockSize() int {
    return gcm.GCMBlockSize
}

func (g *ghash) Reset() {
    g.y = gcm.GCMFieldElement{}
    g.remainIdx = 0
    g.written = 0
}

func (g *ghash) Write(b []byte) (n int, err error) {
    if g.remainIdx > 0 {
        n = copy(g.remains[g.remainIdx:], b)
        g.written += n
        g.remainIdx += n

        if g.remainIdx < gcm.GCMBlockSize {
            return n, nil
        }
        b = b[n:]

        g.gcm.Update(&g.y, g.remains[:])
        g.remainIdx = 0
    }

    fullBlocks := (len(b) / gcm.GCMBlockSize) * gcm.GCMBlockSize
    if fullBlocks > 0 {
        g.gcm.Update(&g.y, b[:fullBlocks])
        n += fullBlocks
        g.written += fullBlocks
        b = b[fullBlocks:]
    }

    if len(b) > 0 {
        g.remainIdx = copy(g.remains[:], b)
        n += g.remainIdx
    }

    return
}

func (g *ghash) Sum(b []byte) []byte {
    yy := g.y

    written := g.written + g.remainIdx

    if g.remainIdx > 0 {
        g.gcm.Update(&yy, g.remains[:g.remainIdx])
    }

    ret, out := SliceForAppend(b, len(b)+gcm.GCMBlockSize)
    g.gcm.Finish(out, &yy, 0, written, &g.tagMask)

    return ret
}

func SliceForAppend(in []byte, n int) (head, tail []byte) {
    if total := len(in) + n; cap(in) >= total {
        head = in[:total]
    } else {
        head = make([]byte, total)
        copy(head, in)
    }

    tail = head[len(in):]
    return
}
