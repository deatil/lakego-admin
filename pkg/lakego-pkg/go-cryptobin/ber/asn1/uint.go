package asn1

func encodeUint(n uint) []byte {
    length := uintLength(n)
    buf := make([]byte, length)
    for i := 0; i < length; i++ {
        shift := (length - 1 - i) * 8
        buf[i] = byte(n >> shift)
    }

    return buf
}

func uintLength(n uint) (length int) {
    length = 1
    for n > 255 {
        length++
        n >>= 8
    }
    return
}
