package saferplus

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
    return (x << n) | (x >> (8 - n));
}

func rotl16(x uint16, n uint16) uint16 {
    return (x << n) | (x >> (16 - n));
}

func rotl32(x uint32, n uint32) uint32 {
    return (x << n) | (x >> (32 - n));
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
