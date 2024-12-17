package xoodyak

import (
    "errors"
    "fmt"

    "github.com/deatil/go-cryptobin/cipher/xoodoo/xoodoo"
)

// Package xoodyak implements the Xoodyak cryptographic suite. Xoodyak is the Cyclist operating mode
// utilizing the Xoodoo state permutation function to power a collection of building block functions. All
// functions described in the Xoodyak specification are implemented in this package:
// https://eprint.iacr.org/2018/767.pdf
// Xoodyak can operate in one of two modes: hashing or keyed mode  which is configured as part of the Xoodyak
// object. Some functions are only available in one particular mode and will panic if invoked while
// Xoodyak is configured incorrectly.
// Using the Cyclist functions, Xoodyak can be configured into a variety of more standard cryptographic
// primitives such as:
//    - Hashing
//    - Message Authentication Code generation
//    - Authenticated Encryption
// The hashing and AEAD primitives provided here are intended to be compatible with Xoodyak entry
// in NIST Lightweight Cryptography competition
// https://csrc.nist.gov/projects/lightweight-cryptography

const (
    xoodyakHashIn        = 16
    xoodyakRkIn          = 44
    xoodyakRkOut         = 24
    xoodyakRatchet       = 16
    AbsorbCdInit   uint8 = 0x03
    AbsorbCdMain   uint8 = 0x00
    SqueezeCuInit  uint8 = 0x40
    CryptCuInit    uint8 = 0x80
    CryptCuMain    uint8 = 0x00
    CryptCd        uint8 = 0x00
    RatchetCu      uint8 = 0x10
)

// CyclistMode defines if a Xoodyak instance should be running in hashing mode or encryption (keyed)
// modes
type CyclistMode int

const (
    Hash CyclistMode = iota + 1
    Keyed
)

// CyclistPhase defines if a Xoodyak instance should perform the Up or Down method in the current
// Cyclist iteration
type CyclistPhase int

const (
    Down CyclistPhase = iota + 1
    Up
)

// CryptMode defines if a Xoodyak instance (already running in keyed mode) is encrypting or decrypting
// provided message data
type CryptMode int

const (
    Encrypting CryptMode = iota + 1
    Decrypting
)

// Xoodyak is a cryptographic object that allows execution of the Cyclist operating mode on the
// Xoodoo permutation primitive. Xoodyak allows for construction of a variety of hashing, encryption
// and authentication schemes through assembly of its various operating methods
type Xoodyak struct {
    Instance    *xoodoo.Xoodoo
    Mode        CyclistMode
    Phase       CyclistPhase
    AbsorbSize  uint
    SqueezeSize uint
}

// Standard Xoodyak Interfaces

// Instantiate generate a new Xoodoo object initialized for hashing or
// keyed operations
func Instantiate(key, id, counter []byte) *Xoodyak {
    newXK := Xoodyak{}
    newXK.Instance, _ = xoodoo.NewXoodoo(xoodoo.MaxRounds, [48]byte{})
    newXK.Mode = Hash
    newXK.Phase = Up
    newXK.AbsorbSize = xoodyakHashIn
    newXK.SqueezeSize = xoodyakHashIn
    if len(key) != 0 {
        newXK.AbsorbKey(key, id, counter)
    }
    return &newXK
}

// Absorb ingests a provided message at the rate of the Xoodyak instance's absorption size
func (xk *Xoodyak) Absorb(x []byte) {
    xk.AbsorbAny(x, xk.AbsorbSize, AbsorbCdInit)
}

// Encrypt transforms the provided plaintext message into a ciphertext message of equal size
// based on the Xoodyak instance provided (key, nonce, counter have already been processed)
func (xk *Xoodyak) Encrypt(pt []byte) []byte {
    if xk.Mode != Keyed {
        panic(errors.New("go-cryptobin/xoodyak: encrypt only available in keyed mode"))
    }
    return xk.Crypt(pt, Encrypting)
}

// Decrypt transforms the provided ciphertext message into a plainext message of equal size
// based on the Xoodyak instance provided (key, nonce, counter have already been processed)
func (xk *Xoodyak) Decrypt(ct []byte) []byte {
    if xk.Mode != Keyed {
        panic(errors.New("go-cryptobin/xoodyak: decrypt only available in keyed mode"))
    }
    return xk.Crypt(ct, Decrypting)
}

// Squeeze outputs a provided stream of pseudo-random bytes at the rate of the Xoodyak instance's squeeze
// size
func (xk *Xoodyak) Squeeze(outLen uint) []byte {
    return xk.SqueezeAny(outLen, SqueezeCuInit)
}

// SqueezeKey can generate a new encryption key from the existing Xoodyak state
func (xk *Xoodyak) SqueezeKey(keyLen uint) []byte {
    if xk.Mode != Keyed {
        panic(errors.New("go-cryptobin/xoodyak: squeeze key only available in keyed mode"))
    }
    return xk.SqueezeAny(keyLen, 0x20)
}

// Ratchet performs a irreversible transformation of the underlying Xoodoo state to prevent key
// recovery
func (xk *Xoodyak) Ratchet() {
    if xk.Mode != Keyed {
        panic(errors.New("go-cryptobin/xoodyak: ratchet only available in keyed mode"))
    }
    ratchetSqueeze := xk.SqueezeAny(xoodyakRatchet, RatchetCu)
    xk.AbsorbAny(ratchetSqueeze, xk.AbsorbSize, AbsorbCdMain)
}

// AbsorbBlock ingests a single block of bytes encompassing a single iteration
// of the Cyclist sequence
func (xk *Xoodyak) AbsorbBlock(x []byte, cd uint8) {
    if xk.Phase != Up {
        xk.Up(0, 0)
    }
    xk.Down(x, cd)
}

// AbsorbAny allow input of any size number of bytes into the
// Xoodoo state
func (xk *Xoodyak) AbsorbAny(x []byte, r uint, cd uint8) {
    var cdTmp uint8 = cd
    var processed uint = 0
    var remaining uint = uint(len(x))
    absorbLen := r
    for {
        if xk.Phase != Up {
            xk.Up(0, 0)
        }
        if remaining < absorbLen {
            absorbLen = remaining
        }
        xk.Down(x[processed:processed+absorbLen], cdTmp)
        cdTmp = AbsorbCdMain
        remaining -= absorbLen
        processed += absorbLen
        if remaining <= 0 {
            break
        }
    }
    return
}

// AbsorbKey is special Xoodyak method that ingests provided key, id (nonce), and counter messages
// into the Xoodoo state enabling the keyed mode of operation typically used for authenticated encryption
func (xk *Xoodyak) AbsorbKey(key, id, counter []byte) {
    if len(key)+len(id) >= xoodyakRkIn {
        panic(fmt.Errorf("go-cryptobin/xoodyak: key and nonce lengths too large - key:%d nonce:%d combined:%d max:%d", len(key), len(id), len(key)+len(id), xoodyakRkIn-1))
    }

    xk.Mode = Keyed
    xk.AbsorbSize = xoodyakRkIn
    xk.SqueezeSize = xoodyakRkOut

    if len(key) > 0 {
        keyIDBuf := append(key, id...)
        keyIDBuf = append(keyIDBuf, byte(len(id)))
        xk.AbsorbAny(keyIDBuf, xk.AbsorbSize, 0x02)
        if len(counter) > 0 {
            xk.AbsorbAny(counter, 1, 0x00)
        }
    }
}

// SqueezeAny allow generation of a message of pseudo-random bytes of any size based on permutating
// the underlying Xoodoo state
func (xk *Xoodyak) SqueezeAny(YLen uint, Cu uint8) []byte {
    squeezeLen := xk.SqueezeSize
    if YLen < squeezeLen {
        squeezeLen = YLen
    }
    output := xk.Up(Cu, squeezeLen)
    var remaining uint = YLen - squeezeLen

    for remaining > 0 {
        xk.Down([]byte{}, 0)
        if remaining < squeezeLen {
            squeezeLen = remaining
        }
        output = append(output, xk.Up(0, squeezeLen)...)
        remaining -= squeezeLen
    }

    return output
}

// Down injects the provided slice of bytes into the provided Xoodoo
// state via xor with the existing state
func (xk *Xoodyak) Down(Xi []byte, Cd byte) {
    if len(Xi) > xoodoo.StateSizeBytes {
        panic(fmt.Errorf("go-cryptobin/xoodyak: input slice size [%d] exceeds Xoodoo state size [%d]", len(Xi), xoodoo.StateSizeBytes))
    }
    cd1 := Cd
    if xk.Mode == Hash {
        cd1 &= 0x01
    }
    fill := make([]byte, xoodoo.StateSizeBytes)
    copy(fill, Xi)
    fill[len(Xi)] = 0x01
    fill[len(fill)-1] = cd1
    xk.Instance.State.XorStateBytes(fill)
    xk.Phase = Down
}

// Up applies the Xoodoo permutation to the Xoodoo state and returns
// the requested number of bytes
func (xk *Xoodyak) Up(Cu byte, Yilen uint) []byte {
    if Yilen > xoodoo.StateSizeBytes {
        panic(fmt.Errorf("go-cryptobin/xoodyak: requested number of bytes [%d] larger than Xoodoo state size [%d]", Yilen, xoodoo.StateSizeBytes))
    }

    if xk.Mode != Hash {
        xk.Instance.State.XorByte(Cu, xoodoo.StateSizeBytes-1)
    }
    xk.Instance.Permutation()
    if Yilen == 0 {
        return []byte{}
    }
    return xk.Instance.Bytes()[:Yilen]

}

// Crypt is core encryption function of Xoodyak/Cyclist. It accepts a byte message of arbitrary
// length and generates either a ciphertext or plaintext based on the mode provided. Encryption or
// decryption is accomplished via XOR against a keystream generated from the Xoodoo primitive
func (xk *Xoodyak) Crypt(msg []byte, cm CryptMode) []byte {
    cuTmp := CryptCuInit
    processed := 0
    remaining := len(msg)
    cryptLen := xoodyakRkOut
    out := make([]byte, remaining)
    for {
        if remaining < cryptLen {
            cryptLen = remaining
        }
        xk.Up(cuTmp, 0)
        xorBytes, _ := xk.Instance.XorExtractBytes(msg[processed : processed+cryptLen])
        if cm == Encrypting {
            xk.Down(msg[processed:processed+cryptLen], CryptCd)
        } else {
            xk.Down(xorBytes, CryptCd)
        }
        copy(out[processed:], xorBytes)
        cuTmp = CryptCuMain
        remaining -= cryptLen
        processed += cryptLen
        if remaining <= 0 {
            break
        }
    }
    return out
}

// CryptBlock executes one step of the encryption/decryption cycle on the provided bytes.
// Useful for building more granular encryption decryption functions
func (xk *Xoodyak) CryptBlock(msg []byte, cu uint8, cm CryptMode) ([]byte, error) {
    if len(msg) > xoodyakRkOut {
        return nil, fmt.Errorf("go-cryptobin/xoodyak: input size [%d] exceeds Xoodoo max encryption block size [%d]", len(msg), xoodyakRkOut)
    }
    xk.Up(cu, 0)
    xorBytes, _ := xk.Instance.XorExtractBytes(msg)
    if cm == Encrypting {
        xk.Down(msg, CryptCd)
    } else {
        xk.Down(xorBytes, CryptCd)
    }
    return xorBytes, nil
}
