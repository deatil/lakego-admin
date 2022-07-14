package crc

// BCC 算法
func BCC(data []byte) uint8 {
    var bcc = byte(0)

    for _, d := range data {
        bcc ^= byte(d)
    }

    return uint8(bcc)
}
