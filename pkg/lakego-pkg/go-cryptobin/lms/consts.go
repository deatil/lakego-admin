package lms

import (
    "hash"
)

const ID_LEN uint64 = 16

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

var D_PBLC = [2]uint8{0x80, 0x80}
var D_MESG = [2]uint8{0x81, 0x81}
var D_LEAF = [2]uint8{0x82, 0x82}
var D_INTR = [2]uint8{0x83, 0x83}
