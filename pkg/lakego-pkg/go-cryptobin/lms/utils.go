package lms

import (
    "hash"
    "encoding/binary"
)

const ID_LEN uint64 = 16

var D_PBLC = [2]uint8{0x80, 0x80}
var D_MESG = [2]uint8{0x81, 0x81}
var D_LEAF = [2]uint8{0x82, 0x82}
var D_INTR = [2]uint8{0x83, 0x83}

// ID is a fixed-legnth []byte used in LM-OTS and LM-OTS
type ID = [ID_LEN]byte

type Hasher = func() hash.Hash

// ByteWindow is the representation of bytes used in calculating LM-OTS signatures
type ByteWindow interface {
    Window() window
    Mask() uint8
}

type window uint8

const (
    WINDOW_W1 window = 1 << iota
    WINDOW_W2
    WINDOW_W4
    WINDOW_W8
)

// Return the actual window value
func (w window) Window() window {
    return w
}

// Return a bit mask (uint8) to bitwise AND with some value
func (w window) Mask() uint8 {
    switch w {
        case WINDOW_W1:
            return 0x01
        case WINDOW_W2:
            return 0x03
        case WINDOW_W4:
            return 0x0f
        case WINDOW_W8:
            return 0xff
        default:
            panic("invalid window")
    }
}

func putu16(ptr []byte, a uint16) {
    binary.BigEndian.PutUint16(ptr, a)
}

func getu32(ptr []byte) uint32 {
    return binary.BigEndian.Uint32(ptr)
}

func putu32(ptr []byte, a uint32) {
    binary.BigEndian.PutUint32(ptr, a)
}

// Returns a []byte representing the Winternitz coefficients of x for a given window, w
func Coefs(x []byte, w ByteWindow) []uint8 {
    mask := w.Mask()
    win := uint64(w.Window())

    entries_per_byte := 8 / win

    n := entries_per_byte * uint64(len(x))
    res := make([]uint8, n)

    for i := uint64(0); i < n; i++ {
        entry := i / entries_per_byte
        offset := i % entries_per_byte
        shift := 8 - win - offset*win
        res[i] = (x[entry] >> shift) & mask
    }

    return res
}

// Returns a checksum calculated over a slice of Winternitz coefficients
func Cksm(coefs []uint8, w ByteWindow, LS uint64) uint16 {
    var sum uint16 = 0
    win := int(w.Window())

    for i := 0; i < len(coefs); i++ {
        sum += (1 << win) - 1 - uint16(coefs[i])
    }

    return sum << int(LS)
}

// expands a message into the winternitz coefficients of the message and its checksum
// returns a slice of length P
func Expand(msg []byte, mode ILmotsParam) ([]uint8, error) {
    params := mode.Params()

    res := Coefs(msg, params.W)

    var cksm [2]byte
    putu16(cksm[:], Cksm(res, params.W, params.LS))

    res = append(res, Coefs(cksm[:], params.W)...)

    return res[:params.P], nil
}
