package vmac

import (
    "fmt"
    "bytes"
    "errors"
    "math/big"
    "crypto/aes"
    "crypto/cipher"
)

// Package vmac is a naive, offline implementation of VMAC
// http://fastcrypto.org/vmac/draft-krovetz-vmac-01.txt

var nonceSizeError = func(n int) error {
    return errors.New(fmt.Sprintf("Nonce must be less than %d bytes", n))
}

type digest struct {
    cipher   cipher.Block
    blocklen int
    nonce    []byte
    size     int
    message  *bytes.Buffer
}

func New(key []byte, nonce []byte, size int) (*digest, error) {
    cipher, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    if len(nonce) >= cipher.BlockSize() {
        return nil, nonceSizeError(cipher.BlockSize())
    }

    if size%8 != 0 {
        return nil, errors.New("Size must be a multiple of 8")
    }

    h := new(digest)
    h.cipher = cipher
    h.blocklen = cipher.BlockSize() * 8
    h.nonce = nonce
    h.size = size
    h.message = bytes.NewBuffer(make([]byte, 0))
    return h, nil
}

func (h *digest) Size() int {
    return h.size
}

func (h *digest) BlockSize() int {
    return h.cipher.BlockSize()
}

func (h *digest) Reset() {
    h.message.Reset()
}

func (h *digest) Write(p []byte) (n int, err error) {
    return h.message.Write(p)
}

func (h *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d := *h
    hash := d.checkSum()
    return append(in, hash...)
}

func (h *digest) checkSum() []byte {
    hashed := h.vhash()
    pad := h.pdf()
    sum := make([]byte, h.size)

    for i := 0; i < h.size/8; i++ {
        lo := 8 * i
        hi := 8 * (i + 1)
        t := new(big.Int).Add(bytesToBigint(pad[lo:hi]), bytesToBigint(hashed[lo:hi]))
        t.Mod(t, m64)
        copy(sum[hi-len(t.Bytes()):hi], t.Bytes())
    }

    return sum
}

func (h *digest) SetNonce(n []byte) error {
    if len(n) >= h.cipher.BlockSize() {
        return nonceSizeError(h.cipher.BlockSize())
    }

    h.nonce = n
    return nil
}

func (h *digest) vhash() []byte {
    y := make([]byte, 0, h.size)
    for i := 0; i < h.size/8; i++ {
        a := h.l1(i)
        b := h.l2(a, h.message.Len()*8, i)
        c := h.l3(b, i)
        y = append(y, c...)
    }

    return y
}

func (h *digest) kdf(index, numbits int) []byte {
    n := (numbits + h.blocklen - 1) / h.blocklen // ceil(numbits / blocklen)
    y := make([]byte, n*h.cipher.BlockSize())

    for i := 0; i < n; i++ {
        block := y[i*h.cipher.BlockSize() : (i+1)*h.cipher.BlockSize()]
        block[0] = byte(index)
        block[h.cipher.BlockSize()-1] = byte(i)
        h.cipher.Encrypt(block, block)
    }

    return y[0 : numbits/8]
}

func (h *digest) pdf() []byte {
    tagsPerBlock := h.cipher.BlockSize() / int(h.size) // for AES tagsPerBlock will be 1 or 2
    mask := byte(tagsPerBlock - 1)                     // assumes tagsPerBlock = 2^i for some integer 0 <= i <= 8
    index := h.nonce[len(h.nonce)-1] & mask

    pad := make([]byte, h.cipher.BlockSize())
    copy(pad[len(pad)-len(h.nonce):], h.nonce)
    pad[len(pad)-1] = pad[len(pad)-1] - index
    h.cipher.Encrypt(pad, pad)

    return pad[int(index)*h.size : int(index)*h.size+h.size]
}

func (h *digest) l1(iter int) []byte {
    tmpk := h.kdf(128, l1keylen+128*iter)
    k := tmpk[16*iter : l1keysize+16*iter]

    t := (h.message.Len() + l1keysize - 1) / l1keysize // ceil(h.message.Len()/l1keysize)
    y := make([]byte, t*16)

    for i := 0; i < t; i++ {
        var mi []byte
        if h.message.Len() < (i+1)*l1keysize {
            mi = h.message.Bytes()[i*l1keysize:]
        } else {
            mi = h.message.Bytes()[i*l1keysize : (i+1)*l1keysize]
        }

        mi = zeroPad(mi)
        mi = endianSwap(mi)
        nhreturn := nh(k, mi)

        copy(y[i*16:(i+1)*16], nhreturn)
    }

    return y
}

func (h *digest) l2(m []byte, length, iter int) []byte {
    tmpt := h.kdf(192, 128*(iter+1))
    t := tmpt[16*iter : 16*(iter+1)]
    for i := 0; i < 16; i += 4 {
        t[i] &= 31
    }

    k := bytesToBigint(t)
    y := big.NewInt(1)

    n := len(m) / 16
    if n != 0 {
        for i := 0; i < n; i++ {
            mi := bytesToBigint(m[16*i : 16*(i+1)])
            y.Mod(y.Add(y.Mul(y, k), mi), p127)
        }
    } else {
        y = k
    }

    y.Add(y, new(big.Int).Lsh(big.NewInt(int64(length%l1keylen)), 64))
    y.Mod(y, p127)

    Y := make([]byte, 16)
    copy(Y[16-len(y.Bytes()):], y.Bytes())
    return Y
}

func (h *digest) l3(m []byte, iter int) []byte {
    i := 0
    k1 := new(big.Int)
    k2 := new(big.Int)

    for need := iter + 1; need > 0; i++ {
        t := h.kdf(224, 128*(i+1))[16*i : 16*(i+1)]
        k1.SetBytes(t[:8])
        k2.SetBytes(t[8:])
        if k1.Cmp(p64) == -1 && k2.Cmp(p64) == -1 {
            need--
        }
    }

    mint := bytesToBigint(m)
    m1 := new(big.Int).Div(mint, p64p32)
    m2 := new(big.Int).Mod(mint, p64p32)

    y := new(big.Int).Add(m1, k1)
    y.Mul(y, new(big.Int).Add(m2, k2))
    y.Mod(y, p64)

    Y := make([]byte, 8)
    copy(Y[8-len(y.Bytes()):], y.Bytes())
    return Y
}
