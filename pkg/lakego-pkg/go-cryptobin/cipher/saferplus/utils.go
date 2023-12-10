package saferplus

import (
    "math/bits"
)

// unsigned char = uint8
// unsigned short = uint16
// unsigned int = uint32

func pht(x *uint8, y *uint8) {
    (*y) += (*x)
    (*x) += (*y)
}

func ipht(x *uint8, y *uint8) {
    (*x) -= (*y)
    (*y) -= (*x)
}

func rotl8(x uint8, n uint8) uint8 {
    return bits.RotateLeft8(x, int(n))
}

func rotl16(x uint16, n uint16) uint16 {
    return bits.RotateLeft16(x, int(n))
}

func rotl32(x uint32, n uint32) uint32 {
    return bits.RotateLeft32(x, int(n))
}

func rotr8(x uint8, n uint8) uint8 {
    return rotl8(x, 8 - n);
}

func rotr16(x uint16, n uint16) uint16 {
    return rotl16(x, 16 - n);
}

func rotr32(x uint32, n uint32) uint32 {
    return rotl32(x, 32 - n);
}

var (
    exp_tab [256]uint8
    log_tab [256]uint8
)

func init_tab() {
    var exp_val uint = 1;

    for i := 0; i < TAB_LEN; i++ {
        exp_tab[i] = uint8(exp_val & 0xFF);
        log_tab[uint(exp_tab[i])] = uint8(i);

        exp_val = exp_val * 45 % 257;
    }
}
