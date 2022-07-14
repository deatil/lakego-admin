package crc

// Name:    Crc3     x^3 + x^1 + x^0
// Poly:    0x03
// Init:    0x00
// Refin:   False
// Refout:  False
// Xorout:  0x00
func Crc3(data []byte) uint8 {
    // 5 = 8 - 3
    var poly = uint8(0x03) << 5

    var i uint8
    var crc = uint8(0x00)

    for _, d := range data {
        crc ^= d
        for i = 0; i < 8; i++ {
            if (crc & 0x80) != 0 {
                crc = (crc << 1) ^ poly
            } else {
                crc <<= 1
            }
        }
    }

    // 计算出的 crc 在高5位，要右移恢复
    return crc >> 5
}

// Name:    CRC-4/ITU           x4+x+1
// Poly:    0x03
// Init:    0x00
// Refin:   True
// Refout:  True
// Xorout:  0x00
func Crc4Itu(data []byte) uint8 {
    var i uint8
    var crc = uint8(0)

    for _, d := range data {
        // crc ^= *data; data++;
        crc ^= d
        for i = 0; i < 8; i ++ {
            if (crc & 0x01) != 0 {
                // 0x0C = (reverse 0x03)>>(8-4)
                crc = (crc >> 1) ^ 0x0C
            } else {
                crc >>= 1
            }
        }
    }

    return crc
}

// Name:    CRC-5/EPC           x5+x3+1
// Poly:    0x09
// Init:    0x09
// Refin:   False
// Refout:  False
// Xorout:  0x00
func Crc5Epc(data []byte) uint8 {
    var i uint8
    var crc = uint8(0x48)

    for _, d := range data {
        // crc ^= *data; data++;
        crc ^= d
        for i = 0; i < 8; i++ {
            if (crc & 0x80) != 0 {
                // 0x48 = 0x09<<(8-5)
                crc = (crc << 1) ^ 0x48
            } else {
                crc <<= 1
            }
        }
    }

    return crc >> 3
}

// Name:    CRC-5/ITU           x5+x4+x2+1
// Poly:    0x15
// Init:    0x00
// Refin:   True
// Refout:  True
// Xorout:  0x00
func Crc5Itu(data []byte) uint8 {
    var i uint8
    var crc = uint8(0)

    for _, d := range data {
        // crc ^= *data; data++;
        crc ^= d
        for i = 0; i < 8; i++ {
            if (crc & 1) != 0 {
                // 0x15 = (reverse 0x15)>>(8-5)
                crc = (crc >> 1) ^ 0x15
            } else {
                crc >>= 1
            }
        }
    }

    return crc
}

// Name:    CRC-5/USB           x5+x2+1
// Poly:    0x05
// Init:    0x1F
// Refin:   True
// Refout:  True
// Xorout:  0x1F
func Crc5Usb(data []byte) uint8 {
    var i uint8
    var crc = uint8(0x1F)

    for _, d := range data {
        // crc ^= *data; data++;
        crc ^= d
        for i = 0; i < 8; i ++ {
            if (crc & 1) != 0 {
                // 0x14 = (reverse 0x05)>>(8-5)
                crc = (crc >> 1) ^ 0x14
            } else {
                crc >>= 1
            }
        }
    }

    return crc ^ 0x1F
}

// Name:    CRC-6/ITU           x6+x+1
// Poly:    0x03
// Init:    0x00
// Refin:   True
// Refout:  True
// Xorout:  0x00
func Crc6Itu(data []byte) uint8 {
    var i uint8
    var crc = uint8(0)

    for _, d := range data {
        // crc ^= *data; data++;
        crc ^= d
        for i = 0; i < 8; i ++ {
            if (crc & 1) != 0 {
                // 0x30 = (reverse 0x03)>>(8-6)
                crc = (crc >> 1) ^ 0x30
            } else {
                crc >>= 1
            }
        }
    }

    return crc
}

// Name:    CRC-7/MMC           x7+x3+1
// Poly:    0x09
// Init:    0x00
// Refin:   False
// Refout:  False
// Xorout:  0x00
// Use:     MultiMediaCard,SD,ect.
func Crc7Mmc(data []byte) uint8 {
    var i uint8
    var crc = uint8(0)

    for _, d := range data {
        // crc ^= *data; data++;
        crc ^= d
        for i = 0; i < 8; i++ {
            if (crc & 0x80) != 0 {
                // 0x12 = 0x09<<(8-7)
                crc = (crc << 1) ^ 0x12
            } else {
                crc <<= 1
            }
        }
    }

    return crc >> 1
}
