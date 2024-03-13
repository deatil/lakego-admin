package misty1

func fi(fin, fkey uint16) uint16 {
    d9 := fin >> 7
    d7 := fin & 0x7f
    d9 = s9table[d9] ^ d7
    d7 = s7table[d7] ^ d9
    d7 = d7 & 0x7f
    d7 = d7 ^ (fkey >> 9)
    d9 = d9 ^ (fkey & 0x1ff)
    d9 = s9table[d9] ^ d7
    fout := (d7 << 9) | d9
    return fout
}

// big-endian

func getUint32(b []byte) uint32 {
    return uint32(b[3])       |
           uint32(b[2]) <<  8 |
           uint32(b[1]) << 16 |
           uint32(b[0]) << 24
}

func putUint32(b []byte, v uint32) {
    b[0] = byte(v >> 24)
    b[1] = byte(v >> 16)
    b[2] = byte(v >>  8)
    b[3] = byte(v)
}
