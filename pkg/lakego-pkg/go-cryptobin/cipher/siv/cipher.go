package siv

import (
    "hash"
    "errors"
    "crypto/cipher"
    "crypto/subtle"

    "github.com/deatil/go-cryptobin/tool/alias"
    "github.com/deatil/go-cryptobin/hash/cmac"
    "github.com/deatil/go-cryptobin/hash/pmac"
)

// MaxAssociatedDataItems is the maximum number of associated data items
const MaxAssociatedDataItems = 126

var (
    // ErrNotAuthentic indicates a ciphertext is malformed or corrupt
    ErrNotAuthentic = errors.New("siv: authentication failed")

    // ErrTooManyAssociatedDataItems indicates more than MaxAssociatedDataItems were given
    ErrTooManyAssociatedDataItems = errors.New("siv: too many associated data items")
)

// Cipher is an instance of AES-SIV, configured with either AES-CMAC or
// AES-PMAC as a message authentication code.
type Cipher struct {
    // MAC function used to derive a synthetic IV and authenticate the message
    h hash.Hash

    // Block cipher function used to encrypt the message
    b cipher.Block

    // Internal buffers
    tmp1, tmp2 pmac.Block
}

// NewCMACCipher returns a new SIV cipher.
func NewCMACCipher(macBlock, ctrBlock cipher.Block) (c *Cipher, err error) {
    c = new(Cipher)
    h, err := cmac.New(macBlock)
    if err != nil {
        return nil, err
    }

    c.h = h
    c.b = ctrBlock

    blocksize := macBlock.BlockSize()
    c.tmp1 = pmac.NewBlock(blocksize)
    c.tmp2 = pmac.NewBlock(blocksize)

    return c, nil
}

// NewPMACCipher returns a new SIV cipher.
func NewPMACCipher(macBlock, ctrBlock cipher.Block) (c *Cipher, err error) {
    c = new(Cipher)
    h, err := pmac.New(macBlock)
    if err != nil {
        return nil, err
    }

    c.h = h
    c.b = ctrBlock

    blocksize := macBlock.BlockSize()
    c.tmp1 = pmac.NewBlock(blocksize)
    c.tmp2 = pmac.NewBlock(blocksize)

    return c, nil
}

// Overhead returns the difference between plaintext and ciphertext lengths.
func (c *Cipher) Overhead() int {
    return c.h.Size()
}

// Seal encrypts and authenticates plaintext, authenticates the given
// associated data items, and appends the result to dst, returning the updated
// slice.
//
// The plaintext and dst may alias exactly or not at all.
//
// For nonce-based encryption, the nonce should be the last associated data item.
func (c *Cipher) Seal(dst []byte, plaintext []byte, data ...[]byte) ([]byte, error) {
    if len(data) > MaxAssociatedDataItems {
        return nil, ErrTooManyAssociatedDataItems
    }

    // Authenticate
    iv := c.s2v(data, plaintext)
    ret, out := alias.SliceForAppend(dst, len(iv)+len(plaintext))
    copy(out, iv)

    // Encrypt
    zeroIVBits(iv)

    ctr := cipher.NewCTR(c.b, iv)
    ctr.XORKeyStream(out[len(iv):], plaintext)

    return ret, nil
}

// Open decrypts ciphertext, authenticates the decrypted plaintext and the given
// associated data items and, if successful, appends the resulting plaintext
// to dst, returning the updated slice. The additional data items must match the
// items passed to Seal.
//
// The ciphertext and dst may alias exactly or not at all.
//
// For nonce-based encryption, the nonce should be the last associated data item.
func (c *Cipher) Open(dst []byte, ciphertext []byte, data ...[]byte) ([]byte, error) {
    if len(data) > MaxAssociatedDataItems {
        return nil, ErrTooManyAssociatedDataItems
    }
    if len(ciphertext) < c.Overhead() {
        return nil, ErrNotAuthentic
    }

    // Decrypt
    iv := c.tmp1.Data[:c.Overhead()]
    copy(iv, ciphertext)
    zeroIVBits(iv)

    ctr := cipher.NewCTR(c.b, iv)

    ret, out := alias.SliceForAppend(dst, len(ciphertext)-len(iv))
    ctr.XORKeyStream(out, ciphertext[len(iv):])

    // Authenticate
    expected := c.s2v(data, out)
    if subtle.ConstantTimeCompare(ciphertext[:len(iv)], expected) != 1 {
        return nil, ErrNotAuthentic
    }

    return ret, nil
}

func (c *Cipher) s2v(s [][]byte, sn []byte) []byte {
    h := c.h
    h.Reset()

    tmp, d := c.tmp1, c.tmp2
    tmp.Clear()

    _, err := h.Write(tmp.Data)
    if err != nil {
        panic(err)
    }

    copy(d.Data, h.Sum(d.Data[:0]))
    h.Reset()

    for _, v := range s {
        _, err := h.Write(v)
        if err != nil {
            panic(err)
        }

        copy(tmp.Data, h.Sum(tmp.Data[:0]))
        h.Reset()
        d.Dbl()

        xor(d.Data, tmp.Data)
    }

    tmp.Clear()

    if len(sn) >= h.BlockSize() {
        n := len(sn) - len(d.Data)
        copy(tmp.Data, sn[n:])
        _, err = h.Write(sn[:n])
        if err != nil {
            panic(err)
        }
    } else {
        copy(tmp.Data, sn)
        tmp.Data[len(sn)] = 0x80
        d.Dbl()
    }

    xor(tmp.Data, d.Data)

    _, err = h.Write(tmp.Data)
    if err != nil {
        panic(err)
    }

    return h.Sum(tmp.Data[:0])
}

func zeroIVBits(iv []byte) {
    // "We zero-out the top bit in each of the last two 32-bit words
    // of the IV before assigning it to Ctr"
    //  — http://web.cs.ucdavis.edu/~rogaway/papers/siv.pdf
    iv[len(iv)-8] &= 0x7f
    iv[len(iv)-4] &= 0x7f
}

// XOR the contents of b into a in-place
func xor(a, b []byte) {
    subtle.XORBytes(a, a, b)
}
